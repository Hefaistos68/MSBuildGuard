using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Contains unit tests for <see cref="NuGetPackageMetadataParser"/>.
	/// </summary>
	[TestFixture]
	public sealed class NuGetPackageMetadataParserTests
	{
		/// <summary>
		/// Verifies package metadata is parsed from a restored package metadata file.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnMetadata_WhenContentContainsSourceAndContentHash()
		{
			var parser = new NuGetPackageMetadataParser();
			var content = """
				{
				  "version": "2",
				  "contentHash": "hash-a",
				  "source": "https://api.nuget.org/v3/index.json"
				}
				""";

			var metadata = parser.ParseContent(content);

			metadata.Version.ShouldBe("2");
			metadata.ContentHash.ShouldBe("hash-a");
			metadata.Source.ShouldBe("https://api.nuget.org/v3/index.json");
		}

		/// <summary>
		/// Verifies missing metadata fields are handled without failure.
		/// </summary>
		[Test]
		public void ParseContent_ShouldReturnEmptyValues_WhenContentOmitsFields()
		{
			var parser = new NuGetPackageMetadataParser();
			var metadata = parser.ParseContent("{ \"version\": \"2\" }");

			metadata.Version.ShouldBe("2");
			metadata.ContentHash.ShouldBeEmpty();
			metadata.Source.ShouldBeEmpty();
		}
	}
}
