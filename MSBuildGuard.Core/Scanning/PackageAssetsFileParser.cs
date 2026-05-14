using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Parses restored NuGet assets metadata from a <c>project.assets.json</c> file.
	/// </summary>
	public sealed class PackageAssetsFileParser
	{
		/// <summary>
		/// Parses package asset provenance records from the specified assets file.
		/// </summary>
		/// <param name="assetsFilePath">The path to the <c>project.assets.json</c> file.</param>
		/// <returns>A collection of parsed package asset provenance records.</returns>
		public IReadOnlyList<PackageAssetProvenanceRecord> Parse(string assetsFilePath)
		{
			if (assetsFilePath == null)
			{
				throw new ArgumentNullException(nameof(assetsFilePath));
			}

			var content = File.ReadAllText(assetsFilePath);

			return ParseContent(content);
		}

		/// <summary>
		/// Parses package asset provenance records from raw assets file content.
		/// </summary>
		/// <param name="content">The raw JSON content.</param>
		/// <returns>A collection of parsed package asset provenance records.</returns>
		public IReadOnlyList<PackageAssetProvenanceRecord> ParseContent(string content)
		{
			if (content == null)
			{
				throw new ArgumentNullException(nameof(content));
			}

			using var document = JsonDocument.Parse(content);

			if (!document.RootElement.TryGetProperty("targets", out var targetsElement) ||
				targetsElement.ValueKind != JsonValueKind.Object)
			{
				return Array.Empty<PackageAssetProvenanceRecord>();
			}

			if (!document.RootElement.TryGetProperty("project", out var projectElement) ||
				projectElement.ValueKind != JsonValueKind.Object)
			{
				return Array.Empty<PackageAssetProvenanceRecord>();
			}

			var projectPath = GetProjectPath(projectElement);
			var restorePath = GetRestorePath(projectElement);
			var directPackageIds = GetDirectPackageIds(projectElement);
			var records = new List<PackageAssetProvenanceRecord>();

			foreach (var targetProperty in targetsElement.EnumerateObject())
			{
				if (targetProperty.Value.ValueKind != JsonValueKind.Object)
				{
					continue;
				}

				foreach (var libraryProperty in targetProperty.Value.EnumerateObject())
				{
					if (libraryProperty.Value.ValueKind != JsonValueKind.Object)
					{
						continue;
					}

					var packageIdentity = PackageIdentity.Parse(libraryProperty.Name);
					var runtimeTarget = targetProperty.Name;
					var isTransitivePackage = !directPackageIds.Contains(packageIdentity.PackageId);

					AddAssetRecords(records, libraryProperty.Value, packageIdentity, runtimeTarget, restorePath, projectPath, isTransitivePackage, "build");
					AddAssetRecords(records, libraryProperty.Value, packageIdentity, runtimeTarget, restorePath, projectPath, isTransitivePackage, "buildTransitive");
					AddAssetRecords(records, libraryProperty.Value, packageIdentity, runtimeTarget, restorePath, projectPath, isTransitivePackage, "buildMultiTargeting");
					AddAssetRecords(records, libraryProperty.Value, packageIdentity, runtimeTarget, restorePath, projectPath, isTransitivePackage, "analyzers");
					AddAssetRecords(records, libraryProperty.Value, packageIdentity, runtimeTarget, restorePath, projectPath, isTransitivePackage, "tools");
				}
			}

			return records
				.OrderBy(record => record.PackageId, StringComparer.OrdinalIgnoreCase)
				.ThenBy(record => record.PackageVersion, StringComparer.OrdinalIgnoreCase)
				.ThenBy(record => record.AssetPath, StringComparer.OrdinalIgnoreCase)
				.ToArray();
		}

		private static void AddAssetRecords(
			IList<PackageAssetProvenanceRecord> records,
			JsonElement libraryElement,
			PackageIdentity packageIdentity,
			string runtimeTarget,
			string restorePath,
			string projectPath,
			bool isTransitivePackage,
			string propertyName)
		{
			if (!libraryElement.TryGetProperty(propertyName, out var assetGroup) ||
				assetGroup.ValueKind != JsonValueKind.Object)
			{
				return;
			}

			foreach (var assetProperty in assetGroup.EnumerateObject())
			{
				if (!IsMsBuildRelatedAsset(assetProperty.Name) && !string.Equals(propertyName, "analyzers", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				records.Add(new PackageAssetProvenanceRecord
				{
					AssetKind          = MapAssetKind(propertyName),
					AssetPath          = assetProperty.Name.Replace('/', Path.DirectorySeparatorChar),
					IntroducedViaProject = projectPath,
					IsTransitivePackage = isTransitivePackage,
					NuGetAssetPath     = CombineRestorePath(restorePath, packageIdentity.PackageId, packageIdentity.PackageVersion, assetProperty.Name),
					PackageId          = packageIdentity.PackageId,
					PackageVersion     = packageIdentity.PackageVersion,
					RuntimeTarget      = runtimeTarget
				});
			}
		}

		private static string CombineRestorePath(string restorePath, string packageId, string packageVersion, string assetPath)
		{
			if (string.IsNullOrWhiteSpace(restorePath))
			{
				return string.Empty;
			}

			var normalizedAssetPath = assetPath.Replace('/', Path.DirectorySeparatorChar);

			return Path.Combine(restorePath, packageId.ToLowerInvariant(), packageVersion.ToLowerInvariant(), normalizedAssetPath);
		}

		private static ISet<string> GetDirectPackageIds(JsonElement projectElement)
		{
			var directPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

			if (!projectElement.TryGetProperty("frameworks", out var frameworksElement) ||
				frameworksElement.ValueKind != JsonValueKind.Object)
			{
				return directPackageIds;
			}

			foreach (var frameworkProperty in frameworksElement.EnumerateObject())
			{
				if (frameworkProperty.Value.ValueKind != JsonValueKind.Object)
				{
					continue;
				}

				if (!frameworkProperty.Value.TryGetProperty("dependencies", out var dependenciesElement) ||
					dependenciesElement.ValueKind != JsonValueKind.Object)
				{
					continue;
				}

				foreach (var dependencyProperty in dependenciesElement.EnumerateObject())
				{
					directPackageIds.Add(dependencyProperty.Name);
				}
			}

			return directPackageIds;
		}

		private static string GetProjectPath(JsonElement projectElement)
		{
			if (!projectElement.TryGetProperty("restore", out var restoreElement) ||
				restoreElement.ValueKind != JsonValueKind.Object)
			{
				return string.Empty;
			}

			if (!restoreElement.TryGetProperty("projectPath", out var projectPathElement) ||
				projectPathElement.ValueKind != JsonValueKind.String)
			{
				return string.Empty;
			}

			return projectPathElement.GetString() ?? string.Empty;
		}

		private static string GetRestorePath(JsonElement projectElement)
		{
			if (!projectElement.TryGetProperty("restore", out var restoreElement) ||
				restoreElement.ValueKind != JsonValueKind.Object)
			{
				return string.Empty;
			}

			if (!restoreElement.TryGetProperty("packagesPath", out var packagesPathElement) ||
				packagesPathElement.ValueKind != JsonValueKind.String)
			{
				return string.Empty;
			}

			var packagesPath = packagesPathElement.GetString() ?? string.Empty;

			if (string.IsNullOrWhiteSpace(packagesPath))
			{
				return string.Empty;
			}

			return Path.GetFullPath(packagesPath);
		}

		private static bool IsMsBuildRelatedAsset(string assetPath)
		{
			if (string.IsNullOrWhiteSpace(assetPath))
			{
				return false;
			}

			var extension = Path.GetExtension(assetPath);

			return string.Equals(extension, ".props", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(extension, ".targets", StringComparison.OrdinalIgnoreCase);
		}

		private static PackageAssetKind MapAssetKind(string propertyName)
		{
			switch (propertyName)
			{
				case "build":
					return PackageAssetKind.Build;
				case "buildTransitive":
					return PackageAssetKind.BuildTransitive;
				case "buildMultiTargeting":
					return PackageAssetKind.BuildMultiTargeting;
				case "analyzers":
					return PackageAssetKind.Analyzer;
				case "tools":
					return PackageAssetKind.Tool;
				default:
					return PackageAssetKind.Unknown;
			}
		}

		/// <summary>
		/// Represents a parsed package identity token from the assets file.
		/// </summary>
		private sealed class PackageIdentity
		{
			/// <summary>
			/// Gets or sets the package identifier.
			/// </summary>
			public string PackageId { get; set; } = string.Empty;

			/// <summary>
			/// Gets or sets the package version.
			/// </summary>
			public string PackageVersion { get; set; } = string.Empty;

			/// <summary>
			/// Parses a package identity token in the form <c>PackageId/Version</c>.
			/// </summary>
			/// <param name="value">The package identity token.</param>
			/// <returns>The parsed package identity.</returns>
			public static PackageIdentity Parse(string value)
			{
				if (string.IsNullOrWhiteSpace(value))
				{
					return new PackageIdentity();
				}

				var separatorIndex = value.IndexOf('/');

				if (separatorIndex < 0)
				{
					return new PackageIdentity
					{
						PackageId = value
					};
				}

				return new PackageIdentity
				{
					PackageId      = value.Substring(0, separatorIndex),
					PackageVersion = value.Substring(separatorIndex + 1)
				};
			}
		}
	}

	/// <summary>
	/// Represents one package-provided build asset resolved from a restored assets file.
	/// </summary>
	public sealed class PackageAssetProvenanceRecord
	{
		/// <summary>
		/// Gets or sets the package identifier.
		/// </summary>
		public string PackageId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package version.
		/// </summary>
		public string PackageVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package source label or URL when determinable.
		/// </summary>
		public string PackageSource { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets package source evidence kind.
		/// </summary>
		public PackageSourceEvidenceKind PackageSourceEvidenceKind { get; set; } = PackageSourceEvidenceKind.Unknown;

		/// <summary>
		/// Gets or sets the path that provided package source evidence when available.
		/// </summary>
		public string PackageSourceEvidencePath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package content hash when available.
		/// </summary>
		public string PackageContentHash { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether package source attribution is inferred.
		/// </summary>
		public bool IsPackageSourceInferred { get; set; }

		/// <summary>
		/// Gets or sets the package asset kind.
		/// </summary>
		public PackageAssetKind AssetKind { get; set; } = PackageAssetKind.Unknown;

		/// <summary>
		/// Gets or sets the logical package asset path from the assets file.
		/// </summary>
		public string AssetPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the resolved asset path in the NuGet restore location.
		/// </summary>
		public string NuGetAssetPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether the package is transitive for the project.
		/// </summary>
		public bool IsTransitivePackage { get; set; }

		/// <summary>
		/// Gets or sets the project path that introduced the package graph.
		/// </summary>
		public string IntroducedViaProject { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the runtime target section from which the asset was selected.
		/// </summary>
		public string RuntimeTarget { get; set; } = string.Empty;
	}
}
