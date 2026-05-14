using System;
using System.IO;
using System.Text.Json;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Parses restored NuGet package metadata from a <c>.nupkg.metadata</c> file.
	/// </summary>
	public sealed class NuGetPackageMetadataParser
	{
		/// <summary>
		/// Parses package metadata from the specified metadata file.
		/// </summary>
		/// <param name="metadataFilePath">The path to the <c>.nupkg.metadata</c> file.</param>
		/// <returns>The parsed package metadata record.</returns>
		public NuGetPackageMetadata Parse(string metadataFilePath)
		{
			if (metadataFilePath == null)
			{
				throw new ArgumentNullException(nameof(metadataFilePath));
			}

			var content = File.ReadAllText(metadataFilePath);

			return ParseContent(content);
		}

		/// <summary>
		/// Parses package metadata from raw metadata file content.
		/// </summary>
		/// <param name="content">The raw JSON content.</param>
		/// <returns>The parsed package metadata record.</returns>
		public NuGetPackageMetadata ParseContent(string content)
		{
			if (content == null)
			{
				throw new ArgumentNullException(nameof(content));
			}

			using var document = JsonDocument.Parse(content);
			var result = new NuGetPackageMetadata();

			if (document.RootElement.ValueKind != JsonValueKind.Object)
			{
				return result;
			}

			result.ContentHash = GetStringProperty(document.RootElement, "contentHash");
			result.Source = GetStringProperty(document.RootElement, "source");
			result.Version = GetStringProperty(document.RootElement, "version");

			return result;
		}

		private static string GetStringProperty(JsonElement element, string propertyName)
		{
			if (!element.TryGetProperty(propertyName, out var propertyElement) ||
				propertyElement.ValueKind != JsonValueKind.String)
			{
				return string.Empty;
			}

			return propertyElement.GetString() ?? string.Empty;
		}
	}

	/// <summary>
	/// Represents parsed metadata from a restored NuGet package metadata file.
	/// </summary>
	public sealed class NuGetPackageMetadata
	{
		/// <summary>
		/// Gets or sets the metadata file format version.
		/// </summary>
		public string Version { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package content hash.
		/// </summary>
		public string ContentHash { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package source URL or label.
		/// </summary>
		public string Source { get; set; } = string.Empty;
	}
}
