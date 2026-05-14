using System.Linq;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Contains unit tests for <see cref="PackageAssetsFileParser"/>.
	/// </summary>
	[TestFixture]
	public sealed class PackageAssetsFileParserTests
	{
		/// <summary>
		/// Verifies build asset provenance is parsed from a restored assets file.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnBuildAssetRecords_WhenAssetsFileContainsPackageBuildSections()
		{
			var parser = new PackageAssetsFileParser();
			var content = """
				{
				  "targets": {
					".NETCoreApp,Version=v10.0": {
					  "Contoso.Build/1.2.3": {
						"type": "package",
						"build": {
						  "build/Contoso.Build.props": {},
						  "build/Contoso.Build.targets": {}
						},
						"buildTransitive": {
						  "buildTransitive/Contoso.Build.targets": {}
						}
					  },
					  "Fabrikam.Tools/4.5.6": {
						"type": "package",
						"buildMultiTargeting": {
						  "buildMultiTargeting/Fabrikam.Tools.targets": {}
						}
					  }
					}
				  },
				  "project": {
					"restore": {
					  "projectPath": "C:\\src\\App\\App.csproj",
					  "packagesPath": "C:\\Users\\tester\\.nuget\\packages\\"
					},
					"frameworks": {
					  "net10.0": {
						"dependencies": {
						  "Contoso.Build": {
							"target": "Package",
							"version": "[1.2.3, )"
						  }
						}
					  }
					}
				  }
				}
				""";

			var records = parser.ParseContent(content);

			records.Count.ShouldBe(4);
			records.Count(record => record.PackageId == "Contoso.Build").ShouldBe(3);
			records.Count(record => record.PackageId == "Fabrikam.Tools").ShouldBe(1);
			records.Single(record => record.AssetKind == PackageAssetKind.BuildTransitive).IsTransitivePackage.ShouldBeFalse();
			records.Single(record => record.PackageId == "Fabrikam.Tools").IsTransitivePackage.ShouldBeTrue();
			records.Count(record => record.PackageId == "Contoso.Build" && record.AssetKind == PackageAssetKind.Build).ShouldBe(2);
			records.First(record => record.PackageId == "Contoso.Build" && record.AssetKind == PackageAssetKind.Build).NuGetAssetPath.ShouldContain("contoso.build");
		}

		/// <summary>
		/// Verifies missing target sections are handled without failure.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnEmptyCollection_WhenTargetsSectionIsMissing()
		{
			var parser = new PackageAssetsFileParser();
			var content = """
				{
				  "project": {
					"restore": {
					  "projectPath": "C:\\src\\App\\App.csproj",
					  "packagesPath": "C:\\Users\\tester\\.nuget\\packages\\"
					}
				  }
				}
				""";

			var records = parser.ParseContent(content);

			records.ShouldBeEmpty();
		}
	}
}
