using System;
using System.Collections.Generic;
using System.IO;
using Moq;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Contains unit tests for <see cref="PackageProvenanceResolver"/>.
	/// </summary>
	[TestFixture]
	public sealed class PackageProvenanceResolverTests
	{
		/// <summary>
		/// Verifies restored package metadata is preferred over configuration-only source inference.
		/// </summary>
		[Test]
		public void Resolve_ShouldPreferRestoredMetadata_WhenMetadataAndConfigAreAvailable()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var metadataPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", ".nupkg.metadata");
			var configurationPath = Path.Combine(projectDirectory, "NuGet.config");
			var fileSystem = CreateFileSystem(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				[metadataPath] = """
					{
					  "version": "2",
					  "contentHash": "hash-a",
					  "source": "https://restored.example/v3/index.json"
					}
					""",
				[configurationPath] = """
					<configuration>
					  <packageSources>
						<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
					  </packageSources>
					</configuration>
					"""
			});
			var resolver = new PackageProvenanceResolver(fileSystem.Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe("https://restored.example/v3/index.json");
			result.ContentHash.ShouldBe("hash-a");
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.RestoredMetadata);
			result.IsInferred.ShouldBeFalse();
			result.EvidencePath.ShouldBe(metadataPath);
		}

		/// <summary>
		/// Verifies configuration mapping is used when stronger local evidence is unavailable.
		/// </summary>
		[Test]
		public void Resolve_ShouldUseConfigMapping_WhenRestoredEvidenceIsUnavailable()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var configurationPath = Path.Combine(projectDirectory, "NuGet.config");
			var fileSystem = CreateFileSystem(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				[configurationPath] = """
					<configuration>
					  <packageSources>
						<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
						<add key="Contoso" value="https://pkgs.contoso.test/v3/index.json" />
					  </packageSources>
					  <packageSourceMapping>
						<packageSource key="Contoso">
						  <package pattern="Contoso.*" />
						</packageSource>
					  </packageSourceMapping>
					</configuration>
					"""
			});
			var resolver = new PackageProvenanceResolver(fileSystem.Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe("https://pkgs.contoso.test/v3/index.json");
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.ConfigMapping);
			result.IsInferred.ShouldBeTrue();
			result.EvidencePath.ShouldBe(configurationPath);
		}

		/// <summary>
		/// Verifies lock-file correlation is used when restored metadata is unavailable.
		/// </summary>
		[Test]
		public void Resolve_ShouldUseLockFileCorrelation_WhenMetadataIsUnavailable()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var lockFilePath = Path.Combine(projectDirectory, "packages.App.lock.json");
			var fileSystem = CreateFileSystem(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				[lockFilePath] = """
					{
					  "version": 1,
					  "dependencies": {
						"net10.0": {
						  "Contoso.Build": {
							"type": "Direct",
							"resolved": "1.2.3",
							"contentHash": "lock-hash"
						  }
						}
					  }
					}
					"""
			});
			var resolver = new PackageProvenanceResolver(fileSystem.Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe(string.Empty);
			result.ContentHash.ShouldBe("lock-hash");
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.LockFileCorrelation);
			result.IsInferred.ShouldBeTrue();
			result.EvidencePath.ShouldBe(lockFilePath);
		}

		/// <summary>
		/// Verifies lock-file mismatch falls back to configuration inference.
		/// </summary>
		[Test]
		public void Resolve_ShouldUseConfigFallback_WhenLockFileVersionIsStale()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var lockFilePath = Path.Combine(projectDirectory, "packages.lock.json");
			var configurationPath = Path.Combine(projectDirectory, "NuGet.config");
			var fileSystem = CreateFileSystem(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				[lockFilePath] = """
					{
					  "version": 1,
					  "dependencies": {
						"net10.0": {
						  "Contoso.Build": {
							"type": "Direct",
							"resolved": "9.9.9",
							"contentHash": "stale"
						  }
						}
					  }
					}
					""",
				[configurationPath] = """
					<configuration>
					  <packageSources>
						<add key="Contoso" value="https://pkgs.contoso.test/v3/index.json" />
					  </packageSources>
					  <packageSourceMapping>
						<packageSource key="Contoso">
						  <package pattern="Contoso.*" />
						</packageSource>
					  </packageSourceMapping>
					</configuration>
					"""
			});
			var resolver = new PackageProvenanceResolver(fileSystem.Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe("https://pkgs.contoso.test/v3/index.json");
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.ConfigMapping);
			result.IsInferred.ShouldBeTrue();
			result.EvidencePath.ShouldBe(configurationPath);
		}

		/// <summary>
		/// Verifies nearest NuGet configuration is selected when multiple layers exist.
		/// </summary>
		[Test]
		public void Resolve_ShouldUseNearestConfiguration_WhenMultipleNuGetConfigFilesExist()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var repositoryDirectory = Path.GetDirectoryName(projectDirectory) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var nearestConfigPath = Path.Combine(projectDirectory, "NuGet.config");
			var parentConfigPath = Path.Combine(repositoryDirectory, "NuGet.config");
			var fileSystem = CreateFileSystem(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				[parentConfigPath] = """
					<configuration>
					  <packageSources>
						<add key="Parent" value="https://parent.example/v3/index.json" />
					  </packageSources>
					</configuration>
					""",
				[nearestConfigPath] = """
					<configuration>
					  <packageSources>
						<add key="Child" value="https://child.example/v3/index.json" />
					  </packageSources>
					</configuration>
					"""
			});
			var resolver = new PackageProvenanceResolver(fileSystem.Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe("https://child.example/v3/index.json");
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.SingleConfiguredSource);
			result.IsInferred.ShouldBeTrue();
			result.EvidencePath.ShouldBe(nearestConfigPath);
		}

		/// <summary>
		/// Verifies disabled mapped sources are ignored during source mapping resolution.
		/// </summary>
		[Test]
		public void Resolve_ShouldIgnoreDisabledMappedSource_WhenMappedSourceIsDisabled()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var configurationPath = Path.Combine(projectDirectory, "NuGet.config");
			var fileSystem = CreateFileSystem(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				[configurationPath] = """
					<configuration>
					  <packageSources>
						<add key="Contoso" value="https://disabled.contoso.test/v3/index.json" />
						<add key="Trusted" value="https://trusted.example/v3/index.json" />
					  </packageSources>
					  <disabledPackageSources>
						<add key="Contoso" value="true" />
					  </disabledPackageSources>
					  <packageSourceMapping>
						<packageSource key="Contoso">
						  <package pattern="Contoso.*" />
						</packageSource>
					  </packageSourceMapping>
					</configuration>
					"""
			});
			var resolver = new PackageProvenanceResolver(fileSystem.Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe("https://trusted.example/v3/index.json");
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.SingleConfiguredSource);
			result.IsInferred.ShouldBeTrue();
			result.EvidencePath.ShouldBe(configurationPath);
		}

		/// <summary>
		/// Verifies unknown provenance is returned when no local evidence can be resolved.
		/// </summary>
		[Test]
		public void Resolve_ShouldReturnUnknown_WhenNoProvenanceEvidenceIsAvailable()
		{
			var projectPath = Path.Combine("C:", "src", "App", "App.csproj");
			var projectDirectory = Path.GetDirectoryName(projectPath) ?? string.Empty;
			var assetsPath = Path.Combine(projectDirectory, "obj", "project.assets.json");
			var packageAssetPath = Path.Combine("C:", "src", "App", "packages", "contoso.build", "1.2.3", "build", "Contoso.Build.targets");
			var resolver = new PackageProvenanceResolver(CreateFileSystem(new Dictionary<string, string>()).Object);

			var result = resolver.Resolve(projectPath, assetsPath, "Contoso.Build", "1.2.3", packageAssetPath);

			result.Source.ShouldBe(string.Empty);
			result.ContentHash.ShouldBe(string.Empty);
			result.EvidenceKind.ShouldBe(PackageSourceEvidenceKind.Unknown);
			result.EvidencePath.ShouldBe(string.Empty);
			result.IsInferred.ShouldBeTrue();
		}

		private static Mock<IFileSystem> CreateFileSystem(IDictionary<string, string> files)
		{
			var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);

			fileSystem
				.Setup(system => system.FileExists(It.IsAny<string>()))
				.Returns((string path) => files.ContainsKey(path));

			fileSystem
				.Setup(system => system.ReadAllText(It.IsAny<string>()))
				.Returns((string path) => files[path]);

			fileSystem
				.Setup(system => system.DirectoryExists(It.IsAny<string>()))
				.Returns(false);

			fileSystem
				.Setup(system => system.EnumerateFiles(It.IsAny<string>(), It.IsAny<string>()))
				.Returns(Array.Empty<string>());

			fileSystem
				.Setup(system => system.HasMarkOfTheWeb(It.IsAny<string>()))
				.Returns(false);

			return fileSystem;
		}
	}
}
