using System.Linq;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Contains unit tests for <see cref="NuGetConfigurationParser"/>.
	/// </summary>
	[TestFixture]
	public sealed class NuGetConfigurationParserTests
	{
		/// <summary>
		/// Verifies package sources and source mappings are parsed from NuGet configuration content.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnSourcesAndMappings_WhenConfigurationContainsThem()
		{
			var parser = new NuGetConfigurationParser();
			var content = """
				<configuration>
				  <packageSources>
					<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
					<add key="Contoso" value="https://pkgs.contoso.test/v3/index.json" />
				  </packageSources>
				  <disabledPackageSources>
					<add key="Contoso" value="true" />
				  </disabledPackageSources>
				  <packageSourceMapping>
					<packageSource key="nuget.org">
					  <package pattern="*" />
					</packageSource>
					<packageSource key="Contoso">
					  <package pattern="Contoso.*" />
					  <package pattern="Fabrikam.Tools" />
					</packageSource>
				  </packageSourceMapping>
				</configuration>
				""";

			var configuration = parser.ParseContent(content);

			configuration.PackageSources.Count.ShouldBe(2);
			configuration.PackageSources.Single(source => source.Name == "nuget.org").IsEnabled.ShouldBeTrue();
			configuration.PackageSources.Single(source => source.Name == "Contoso").IsEnabled.ShouldBeFalse();
			configuration.PackageSourceMappings.Count.ShouldBe(2);
			configuration.PackageSourceMappings.Single(mapping => mapping.SourceKey == "Contoso").Patterns.ShouldBe(["Contoso.*", "Fabrikam.Tools"]);
		}

		/// <summary>
		/// Verifies package source matching prefers the most specific configured pattern.
		/// </summary>
		[Test]
		public void FindMatchingSources_ShouldOrderMatchesBySpecificity()
		{
			var parser = new NuGetConfigurationParser();
			var configuration = parser.ParseContent("""
				<configuration>
				  <packageSources>
					<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
					<add key="Contoso" value="https://pkgs.contoso.test/v3/index.json" />
				  </packageSources>
				  <packageSourceMapping>
					<packageSource key="nuget.org">
					  <package pattern="*" />
					</packageSource>
					<packageSource key="Contoso">
					  <package pattern="Contoso.*" />
					  <package pattern="Contoso.Build" />
					</packageSource>
				  </packageSourceMapping>
				</configuration>
				""");

			var matches = parser.FindMatchingSources(configuration, "Contoso.Build");

			matches.Count.ShouldBe(2);
			matches[0].SourceKey.ShouldBe("Contoso");
			matches[1].SourceKey.ShouldBe("nuget.org");
		}
	}
}
