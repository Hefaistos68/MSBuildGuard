using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace MSBuildGuard.Core.Scanning
{
	/// <summary>
	/// Parses package source and mapping metadata from a <c>NuGet.config</c> file.
	/// </summary>
	public sealed class NuGetConfigurationParser
	{
		/// <summary>
		/// Parses package source metadata from the specified configuration file.
		/// </summary>
		/// <param name="configurationFilePath">The path to the <c>NuGet.config</c> file.</param>
		/// <returns>The parsed package source metadata.</returns>
		public NuGetConfiguration Parse(string configurationFilePath)
		{
			if (configurationFilePath == null)
			{
				throw new ArgumentNullException(nameof(configurationFilePath));
			}

			var content = File.ReadAllText(configurationFilePath);

			return ParseContent(content);
		}

		/// <summary>
		/// Parses package source metadata from raw configuration file content.
		/// </summary>
		/// <param name="content">The raw XML content.</param>
		/// <returns>The parsed package source metadata.</returns>
		public NuGetConfiguration ParseContent(string content)
		{
			if (content == null)
			{
				throw new ArgumentNullException(nameof(content));
			}

			var document = XDocument.Parse(content, LoadOptions.None);
			var result = new NuGetConfiguration();
			var root = document.Root;

			if (root == null)
			{
				return result;
			}

			ParsePackageSources(root, result);
			ParsePackageSourceMappings(root, result);

			return result;
		}

		/// <summary>
		/// Finds source mappings for the specified package identifier.
		/// </summary>
		/// <param name="configuration">The parsed configuration to inspect.</param>
		/// <param name="packageId">The package identifier to match.</param>
		/// <returns>The matching source mappings ordered by pattern specificity.</returns>
		public IReadOnlyList<NuGetPackageSourceMapping> FindMatchingSources(NuGetConfiguration configuration, string packageId)
		{
			if (configuration == null)
			{
				throw new ArgumentNullException(nameof(configuration));
			}

			if (packageId == null)
			{
				throw new ArgumentNullException(nameof(packageId));
			}

			var matches = configuration.PackageSourceMappings
				.Where(mapping => MatchesAnyPattern(mapping, packageId))
				.OrderByDescending(mapping => GetBestPatternSpecificity(mapping, packageId))
				.ThenBy(mapping => mapping.SourceKey, StringComparer.OrdinalIgnoreCase)
				.ToArray();

			return matches;
		}

		private static void ParsePackageSources(XElement root, NuGetConfiguration configuration)
		{
			var packageSourcesElement = root.Element("packageSources");

			if (packageSourcesElement == null)
			{
				return;
			}

			var disabledSources = GetDisabledSources(root);

			foreach (var addElement in packageSourcesElement.Elements("add"))
			{
				var key = GetAttributeValue(addElement, "key");
				var value = GetAttributeValue(addElement, "value");

				if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
				{
					continue;
				}

				configuration.PackageSources.Add(new NuGetPackageSource
				{
					Name      = key,
					Source    = value,
					IsEnabled = !disabledSources.Contains(key)
				});
			}
		}

		private static void ParsePackageSourceMappings(XElement root, NuGetConfiguration configuration)
		{
			var mappingsElement = root.Element("packageSourceMapping");

			if (mappingsElement == null)
			{
				return;
			}

			foreach (var sourceElement in mappingsElement.Elements("packageSource"))
			{
				var sourceKey = GetAttributeValue(sourceElement, "key");

				if (string.IsNullOrWhiteSpace(sourceKey))
				{
					continue;
				}

				var mapping = new NuGetPackageSourceMapping
				{
					SourceKey = sourceKey
				};

				foreach (var packageElement in sourceElement.Elements("package"))
				{
					var pattern = GetAttributeValue(packageElement, "pattern");

					if (string.IsNullOrWhiteSpace(pattern))
					{
						continue;
					}

					mapping.Patterns.Add(pattern);
				}

				configuration.PackageSourceMappings.Add(mapping);
			}
		}

		private static ISet<string> GetDisabledSources(XElement root)
		{
			var disabledSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var disabledElement = root.Element("disabledPackageSources");

			if (disabledElement == null)
			{
				return disabledSources;
			}

			foreach (var addElement in disabledElement.Elements("add"))
			{
				var key = GetAttributeValue(addElement, "key");
				var value = GetAttributeValue(addElement, "value");

				if (string.IsNullOrWhiteSpace(key) || !IsDisabledValue(value))
				{
					continue;
				}

				disabledSources.Add(key);
			}

			return disabledSources;
		}

		private static bool MatchesAnyPattern(NuGetPackageSourceMapping mapping, string packageId)
		{
			foreach (var pattern in mapping.Patterns)
			{
				if (MatchesPattern(pattern, packageId))
				{
					return true;
				}
			}

			return false;
		}

		private static int GetBestPatternSpecificity(NuGetPackageSourceMapping mapping, string packageId)
		{
			var best = -1;

			foreach (var pattern in mapping.Patterns)
			{
				var specificity = GetPatternSpecificity(pattern, packageId);

				if (specificity > best)
				{
					best = specificity;
				}
			}

			return best;
		}

		private static int GetPatternSpecificity(string pattern, string packageId)
		{
			if (!MatchesPattern(pattern, packageId))
			{
				return -1;
			}

			if (string.Equals(pattern, packageId, StringComparison.OrdinalIgnoreCase))
			{
				return int.MaxValue;
			}

			if (string.Equals(pattern, "*", StringComparison.Ordinal))
			{
				return 0;
			}

			if (pattern.EndsWith("*", StringComparison.Ordinal))
			{
				return pattern.Length - 1;
			}

			return pattern.Length;
		}

		private static bool MatchesPattern(string pattern, string packageId)
		{
			if (string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(packageId))
			{
				return false;
			}

			if (string.Equals(pattern, "*", StringComparison.Ordinal))
			{
				return true;
			}

			if (pattern.EndsWith("*", StringComparison.Ordinal))
			{
				var prefix = pattern.Substring(0, pattern.Length - 1);

				return packageId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
			}

			return string.Equals(pattern, packageId, StringComparison.OrdinalIgnoreCase);
		}

		private static bool IsDisabledValue(string value)
		{
			return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(value, "1", StringComparison.OrdinalIgnoreCase);
		}

		private static string GetAttributeValue(XElement element, string attributeName)
		{
			return element.Attribute(attributeName)?.Value ?? string.Empty;
		}
	}

	/// <summary>
	/// Represents parsed package source metadata from a <c>NuGet.config</c> file.
	/// </summary>
	public sealed class NuGetConfiguration
	{
		/// <summary>
		/// Gets the configured package sources.
		/// </summary>
		public IList<NuGetPackageSource> PackageSources { get; } = new List<NuGetPackageSource>();

		/// <summary>
		/// Gets the configured package source mappings.
		/// </summary>
		public IList<NuGetPackageSourceMapping> PackageSourceMappings { get; } = new List<NuGetPackageSourceMapping>();
	}

	/// <summary>
	/// Represents one configured package source entry.
	/// </summary>
	public sealed class NuGetPackageSource
	{
		/// <summary>
		/// Gets or sets the configured source name.
		/// </summary>
		public string Name { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the configured source URL or path.
		/// </summary>
		public string Source { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether the source is enabled.
		/// </summary>
		public bool IsEnabled { get; set; } = true;
	}

	/// <summary>
	/// Represents one configured package source mapping entry.
	/// </summary>
	public sealed class NuGetPackageSourceMapping
	{
		/// <summary>
		/// Gets or sets the source key referenced by the mapping.
		/// </summary>
		public string SourceKey { get; set; } = string.Empty;

		/// <summary>
		/// Gets the package patterns associated with the source.
		/// </summary>
		public IList<string> Patterns { get; } = new List<string>();
	}
}
