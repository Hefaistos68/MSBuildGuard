using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Parses package metadata from a <c>packages.lock.json</c> file.
	/// </summary>
	public sealed class NuGetLockFileParser
	{
		/// <summary>
		/// Parses package metadata from raw lock-file content.
		/// </summary>
		/// <param name="content">The raw JSON content.</param>
		/// <returns>The parsed package metadata records.</returns>
		public IReadOnlyList<NuGetLockFilePackage> ParseContent(string content)
		{
			if (content == null)
			{
				throw new ArgumentNullException(nameof(content));
			}

			using var document = JsonDocument.Parse(content);

			if (!document.RootElement.TryGetProperty("dependencies", out var dependenciesElement) ||
				dependenciesElement.ValueKind != JsonValueKind.Object)
			{
				return Array.Empty<NuGetLockFilePackage>();
			}

			var records = new List<NuGetLockFilePackage>();

			foreach (var frameworkProperty in dependenciesElement.EnumerateObject())
			{
				if (frameworkProperty.Value.ValueKind != JsonValueKind.Object)
				{
					continue;
				}

				foreach (var packageProperty in frameworkProperty.Value.EnumerateObject())
				{
					if (packageProperty.Value.ValueKind != JsonValueKind.Object)
					{
						continue;
					}

					var record = new NuGetLockFilePackage
					{
						ContentHash = GetStringProperty(packageProperty.Value, "contentHash"),
						Framework   = frameworkProperty.Name,
						PackageId   = packageProperty.Name,
						Requested   = GetStringProperty(packageProperty.Value, "requested"),
						Resolved    = GetStringProperty(packageProperty.Value, "resolved"),
						Type        = GetStringProperty(packageProperty.Value, "type")
					};

					records.Add(record);
				}
			}

			return records
				.OrderBy(record => record.PackageId, StringComparer.OrdinalIgnoreCase)
				.ThenBy(record => record.Resolved, StringComparer.OrdinalIgnoreCase)
				.ThenBy(record => record.Framework, StringComparer.OrdinalIgnoreCase)
				.ToArray();
		}

		/// <summary>
		/// Parses lock-file content into a lookup-friendly index.
		/// </summary>
		/// <param name="content">The raw JSON content.</param>
		/// <returns>The parsed lock-file index.</returns>
		public NuGetLockFileIndex ParseIndexContent(string content)
		{
			var records = ParseContent(content);
			var index = new NuGetLockFileIndex();

			foreach (var record in records)
			{
				var key = NuGetLockFileIndex.CreateKey(record.PackageId, record.Resolved, record.Framework);
				index.ByPackageVersionFramework[key] = record;
			}

			return index;
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
	/// Represents lookup-friendly lock-file package metadata.
	/// </summary>
	public sealed class NuGetLockFileIndex
	{
		/// <summary>
		/// Gets package records keyed by package id, resolved version, and framework.
		/// </summary>
		public IDictionary<string, NuGetLockFilePackage> ByPackageVersionFramework { get; } = new Dictionary<string, NuGetLockFilePackage>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Tries to get a package record for the provided package identity and framework.
		/// </summary>
		/// <param name="packageId">The package identifier.</param>
		/// <param name="resolvedVersion">The resolved package version.</param>
		/// <param name="framework">The framework section name.</param>
		/// <param name="record">The resulting lock-file record when found.</param>
		/// <returns><see langword="true"/> when a matching record exists; otherwise <see langword="false"/>.</returns>
		public bool TryGet(string packageId, string resolvedVersion, string framework, out NuGetLockFilePackage? record)
		{
			var key = CreateKey(packageId, resolvedVersion, framework);

			if (ByPackageVersionFramework.TryGetValue(key, out var existing))
			{
				record = existing;

				return true;
			}

			record = null;

			return false;
		}

		internal static string CreateKey(string packageId, string resolvedVersion, string framework)
		{
			return string.Concat(packageId ?? string.Empty, "|", resolvedVersion ?? string.Empty, "|", framework ?? string.Empty);
		}
	}

	/// <summary>
	/// Represents one package entry from a <c>packages.lock.json</c> file.
	/// </summary>
	public sealed class NuGetLockFilePackage
	{
		/// <summary>
		/// Gets or sets the target framework section.
		/// </summary>
		public string Framework { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package identifier.
		/// </summary>
		public string PackageId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the requested version range when present.
		/// </summary>
		public string Requested { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the resolved version.
		/// </summary>
		public string Resolved { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package type.
		/// </summary>
		public string Type { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package content hash.
		/// </summary>
		public string ContentHash { get; set; } = string.Empty;
	}
}
