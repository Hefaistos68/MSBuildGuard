using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Resolves package source provenance for restored package assets using evidence-first precedence.
	/// </summary>
	public sealed class PackageProvenanceResolver
	{
		private readonly IFileSystem _fileSystem;
		private readonly NuGetConfigurationParser _nuGetConfigurationParser;
		private readonly NuGetLockFileParser _nuGetLockFileParser;
		private readonly NuGetPackageMetadataParser _nuGetPackageMetadataParser;
		private readonly IDictionary<string, NuGetConfiguration> _nuGetConfigurationCache = new Dictionary<string, NuGetConfiguration>(StringComparer.OrdinalIgnoreCase);
		private readonly IDictionary<string, NuGetLockFileIndex> _nuGetLockFileCache = new Dictionary<string, NuGetLockFileIndex>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Initializes a new instance of the <see cref="PackageProvenanceResolver"/> class.
		/// </summary>
		/// <param name="fileSystem">The file-system abstraction.</param>
		/// <param name="nuGetConfigurationParser">The NuGet configuration parser.</param>
		/// <param name="nuGetLockFileParser">The NuGet lock-file parser.</param>
		/// <param name="nuGetPackageMetadataParser">The restored package metadata parser.</param>
		public PackageProvenanceResolver(
			IFileSystem fileSystem,
			NuGetConfigurationParser? nuGetConfigurationParser = null,
			NuGetLockFileParser? nuGetLockFileParser = null,
			NuGetPackageMetadataParser? nuGetPackageMetadataParser = null)
		{
			_fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
			_nuGetConfigurationParser = nuGetConfigurationParser ?? new NuGetConfigurationParser();
			_nuGetLockFileParser = nuGetLockFileParser ?? new NuGetLockFileParser();
			_nuGetPackageMetadataParser = nuGetPackageMetadataParser ?? new NuGetPackageMetadataParser();
		}

		/// <summary>
		/// Resolves package source attribution for a package asset.
		/// </summary>
		/// <param name="projectPath">The project path that introduced the package graph.</param>
		/// <param name="assetsFilePath">The project assets file path.</param>
		/// <param name="packageId">The package identifier.</param>
		/// <param name="packageVersion">The package version.</param>
		/// <param name="packageAssetPath">The package asset path.</param>
		/// <returns>The source attribution result.</returns>
		public PackageSourceAttributionResult Resolve(string projectPath, string assetsFilePath, string packageId, string packageVersion, string packageAssetPath)
		{
			if (string.IsNullOrWhiteSpace(packageAssetPath))
			{
				return PackageSourceAttributionResult.Unknown();
			}

			var metadataPath = TryGetRestoredMetadataPath(packageAssetPath, packageId, packageVersion);

			if (!string.IsNullOrWhiteSpace(metadataPath) && TryReadRestoredMetadata(metadataPath, out var metadataResult))
			{
				return metadataResult;
			}

			var lockFileResult = TryResolveFromLockFile(projectPath, packageId, packageVersion);

			if (lockFileResult != null)
			{
				return lockFileResult;
			}

			return ResolveFromNuGetConfiguration(projectPath, packageId);
		}

		private bool TryReadRestoredMetadata(string metadataPath, out PackageSourceAttributionResult result)
		{
			result = PackageSourceAttributionResult.Unknown();

			try
			{
				if (!_fileSystem.FileExists(metadataPath))
				{
					return false;
				}

				var metadata = _nuGetPackageMetadataParser.ParseContent(_fileSystem.ReadAllText(metadataPath));

				if (string.IsNullOrWhiteSpace(metadata.Source) && string.IsNullOrWhiteSpace(metadata.ContentHash))
				{
					return false;
				}

				result = new PackageSourceAttributionResult
				{
					ContentHash = metadata.ContentHash,
					EvidenceKind = PackageSourceEvidenceKind.RestoredMetadata,
					EvidencePath = metadataPath,
					IsInferred = false,
					Source = metadata.Source
				};

				return true;
			}
			catch
			{
				return false;
			}
		}

		private PackageSourceAttributionResult? TryResolveFromLockFile(string projectPath, string packageId, string packageVersion)
		{
			if (string.IsNullOrWhiteSpace(projectPath) || string.IsNullOrWhiteSpace(packageId) || string.IsNullOrWhiteSpace(packageVersion))
			{
				return null;
			}

			var lockFilePath = GetLockFilePath(projectPath);

			if (string.IsNullOrWhiteSpace(lockFilePath))
			{
				return null;
			}

			NuGetLockFileIndex index;

			if (!_nuGetLockFileCache.TryGetValue(lockFilePath, out index))
			{
				try
				{
					if (!_fileSystem.FileExists(lockFilePath))
					{
						return null;
					}

					index = _nuGetLockFileParser.ParseIndexContent(_fileSystem.ReadAllText(lockFilePath));
					_nuGetLockFileCache[lockFilePath] = index;
				}
				catch
				{
					return null;
				}
			}

			var matchingRecord = index.ByPackageVersionFramework.Values.FirstOrDefault(record =>
				string.Equals(record.PackageId, packageId, StringComparison.OrdinalIgnoreCase) &&
				string.Equals(record.Resolved, packageVersion, StringComparison.OrdinalIgnoreCase));

			if (matchingRecord == null)
			{
				return null;
			}

			return new PackageSourceAttributionResult
			{
				ContentHash = matchingRecord.ContentHash,
				EvidenceKind = PackageSourceEvidenceKind.LockFileCorrelation,
				EvidencePath = lockFilePath,
				IsInferred = true,
				Source = string.Empty
			};
		}

		private PackageSourceAttributionResult ResolveFromNuGetConfiguration(string projectPath, string packageId)
		{
			if (string.IsNullOrWhiteSpace(projectPath) || string.IsNullOrWhiteSpace(packageId))
			{
				return PackageSourceAttributionResult.Unknown();
			}

			var configurationPath = GetNearestNuGetConfigurationPath(projectPath);

			if (string.IsNullOrWhiteSpace(configurationPath))
			{
				return PackageSourceAttributionResult.Unknown();
			}

			if (!_nuGetConfigurationCache.TryGetValue(configurationPath, out var configuration))
			{
				try
				{
					configuration = _nuGetConfigurationParser.ParseContent(_fileSystem.ReadAllText(configurationPath));
					_nuGetConfigurationCache[configurationPath] = configuration;
				}
				catch
				{
					return PackageSourceAttributionResult.Unknown();
				}
			}

			var enabledSources = configuration.PackageSources.Where(source => source.IsEnabled).ToArray();
			var matchingSources = _nuGetConfigurationParser.FindMatchingSources(configuration, packageId);

			foreach (var sourceMapping in matchingSources)
			{
				var source = enabledSources.FirstOrDefault(candidate => string.Equals(candidate.Name, sourceMapping.SourceKey, StringComparison.OrdinalIgnoreCase));

				if (source == null)
				{
					continue;
				}

				return new PackageSourceAttributionResult
				{
					EvidenceKind = PackageSourceEvidenceKind.ConfigMapping,
					EvidencePath = configurationPath,
					IsInferred = true,
					Source = source.Source
				};
			}

			if (enabledSources.Length == 1)
			{
				return new PackageSourceAttributionResult
				{
					EvidenceKind = PackageSourceEvidenceKind.SingleConfiguredSource,
					EvidencePath = configurationPath,
					IsInferred = true,
					Source = enabledSources[0].Source
				};
			}

			return PackageSourceAttributionResult.Unknown();
		}

		private static string TryGetRestoredMetadataPath(string packageAssetPath, string packageId, string packageVersion)
		{
			if (string.IsNullOrWhiteSpace(packageAssetPath) ||
				string.IsNullOrWhiteSpace(packageId) ||
				string.IsNullOrWhiteSpace(packageVersion))
			{
				return string.Empty;
			}

			var normalizedPackageAssetPath = Path.GetFullPath(packageAssetPath);
			var segments = normalizedPackageAssetPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
			var normalizedPackageId = packageId.ToLowerInvariant();
			var normalizedPackageVersion = packageVersion.ToLowerInvariant();

			for (var index = 0; index < segments.Length - 1; index++)
			{
				if (!string.Equals(segments[index], normalizedPackageId, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				if (!string.Equals(segments[index + 1], normalizedPackageVersion, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				var rootSegments = segments.Take(index + 2).ToArray();
				var packageRootPath = string.Join(Path.DirectorySeparatorChar.ToString(), rootSegments);

				return Path.Combine(packageRootPath, ".nupkg.metadata");
			}

			return string.Empty;
		}

		private string GetLockFilePath(string projectPath)
		{
			var projectDirectory = Path.GetDirectoryName(projectPath);

			if (string.IsNullOrWhiteSpace(projectDirectory))
			{
				return string.Empty;
			}

			var projectName = Path.GetFileNameWithoutExtension(projectPath);
			var projectSpecificLockFileName = string.Format(System.Globalization.CultureInfo.InvariantCulture, "packages.{0}.lock.json", projectName);
			var projectSpecificLockFilePath = Path.Combine(projectDirectory, projectSpecificLockFileName);

			try
			{
				if (_fileSystem.FileExists(projectSpecificLockFilePath))
				{
					return projectSpecificLockFilePath;
				}
			}
			catch
			{
				return string.Empty;
			}

			return Path.Combine(projectDirectory, "packages.lock.json");
		}

		private string GetNearestNuGetConfigurationPath(string projectPath)
		{
			var projectDirectory = Path.GetDirectoryName(projectPath);

			if (string.IsNullOrWhiteSpace(projectDirectory))
			{
				return string.Empty;
			}

			var currentDirectory = projectDirectory;

			while (!string.IsNullOrWhiteSpace(currentDirectory))
			{
				var configurationPath = Path.Combine(currentDirectory, "NuGet.config");

				try
				{
					if (_fileSystem.FileExists(configurationPath))
					{
						return configurationPath;
					}
				}
				catch
				{
					return string.Empty;
				}

				var parentDirectory = Path.GetDirectoryName(currentDirectory);

				if (string.Equals(parentDirectory, currentDirectory, StringComparison.OrdinalIgnoreCase))
				{
					break;
				}

				currentDirectory = parentDirectory;
			}

			return string.Empty;
		}
	}

	/// <summary>
	/// Represents package source attribution details resolved by evidence precedence.
	/// </summary>
	public sealed class PackageSourceAttributionResult
	{
		/// <summary>
		/// Gets or sets the package source label or URL.
		/// </summary>
		public string Source { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets package source evidence strength.
		/// </summary>
		public PackageSourceEvidenceKind EvidenceKind { get; set; } = PackageSourceEvidenceKind.Unknown;

		/// <summary>
		/// Gets or sets the path used as provenance evidence.
		/// </summary>
		public string EvidencePath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets package content hash from provenance evidence.
		/// </summary>
		public string ContentHash { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether package source attribution is inferred.
		/// </summary>
		public bool IsInferred { get; set; }

		/// <summary>
		/// Creates an unknown package source attribution result.
		/// </summary>
		/// <returns>An unknown attribution result.</returns>
		public static PackageSourceAttributionResult Unknown()
		{
			return new PackageSourceAttributionResult
			{
				EvidenceKind = PackageSourceEvidenceKind.Unknown,
				IsInferred = true
			};
		}
	}
}
