using System.Linq;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Contains unit tests for <see cref="NuGetLockFileParser"/>.
	/// </summary>
	[TestFixture]
	public sealed class NuGetLockFileParserTests
	{
		/// <summary>
		/// Verifies package metadata is parsed from lock-file content.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnPackages_WhenDependenciesSectionExists()
		{
			var parser = new NuGetLockFileParser();
			var content = """
				{
				  "version": 1,
				  "dependencies": {
					".NETCoreApp,Version=v10.0": {
					  "Contoso.Build": {
						"type": "Direct",
						"requested": "[1.2.3, )",
						"resolved": "1.2.3",
						"contentHash": "hash-a"
					  },
					  "Fabrikam.Tools": {
						"type": "Transitive",
						"resolved": "4.5.6",
						"contentHash": "hash-b"
					  }
					}
				  }
				}
				""";

			var records = parser.ParseContent(content);

			records.Count.ShouldBe(2);
			records.Single(record => record.PackageId == "Contoso.Build").Requested.ShouldBe("[1.2.3, )");
			records.Single(record => record.PackageId == "Contoso.Build").ContentHash.ShouldBe("hash-a");
			records.Single(record => record.PackageId == "Fabrikam.Tools").Type.ShouldBe("Transitive");
		}

		/// <summary>
		/// Verifies lock-file parser builds a lookup index for package, version, and framework correlation.
		/// </summary>
		[Test]
		public void ParseIndexContent_ShouldBuildPackageLookupIndex()
		{
			var parser = new NuGetLockFileParser();
			var content = """
				{
				  "version": 1,
				  "dependencies": {
					"net10.0": {
					  "Contoso.Build": {
						"resolved": "1.2.3",
						"contentHash": "hash-a"
					  }
					}
				  }
				}
				""";

			var index = parser.ParseIndexContent(content);
			var found = index.TryGet("Contoso.Build", "1.2.3", "net10.0", out var record);

			found.ShouldBeTrue();
			record.ShouldNotBeNull();
			record.ContentHash.ShouldBe("hash-a");
		}

		/// <summary>
		/// Verifies missing dependency sections are handled without failure.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnEmptyCollection_WhenDependenciesSectionIsMissing()
		{
			var parser = new NuGetLockFileParser();
			var records = parser.ParseContent("{ \"version\": 1 }");

			records.ShouldBeEmpty();
		}
	}
}
