using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Applies trust-sharing preferences to .gitignore files in the loaded solution tree.
	/// </summary>
	internal sealed class GitIgnoreTrustSharingService
	{
		private static readonly string[] ManagedTrustIgnoreEntries =
		{
			".msbuildguard",
			"/.msbuildguard/",
			"**/.msbuildguard/trust.json",
			"**/.msbuildguard/trust.json.audit.jsonl"
		};

		/// <summary>
		/// Applies trust-sharing behavior for all .gitignore files under the solution directory.
		/// </summary>
		/// <param name="solutionPath">Loaded solution path.</param>
		/// <param name="allowSharingTrustsInRepositories">When true, removes managed trust ignore entries; when false, adds them.</param>
		/// <returns>The number of .gitignore files changed.</returns>
		public int ApplyForSolution(string solutionPath, bool allowSharingTrustsInRepositories)
		{
			if (string.IsNullOrWhiteSpace(solutionPath) || !File.Exists(solutionPath))
			{
				return 0;
			}

			var solutionDirectory = Path.GetDirectoryName(solutionPath);

			if (string.IsNullOrWhiteSpace(solutionDirectory) || !Directory.Exists(solutionDirectory))
			{
				return 0;
			}

			var gitIgnoreFiles = Directory.EnumerateFiles(solutionDirectory, ".gitignore", SearchOption.AllDirectories).ToList();
			var changedCount = 0;

			foreach (var gitIgnoreFile in gitIgnoreFiles)
			{
				if (UpdateGitIgnoreFile(gitIgnoreFile, allowSharingTrustsInRepositories))
				{
					changedCount++;
				}
			}

			return changedCount;
		}

		private static bool UpdateGitIgnoreFile(string gitIgnorePath, bool allowSharingTrustsInRepositories)
		{
			if (string.IsNullOrWhiteSpace(gitIgnorePath) || !File.Exists(gitIgnorePath))
			{
				return false;
			}

			var lines = File.ReadAllLines(gitIgnorePath).ToList();
			var originalCount = lines.Count;
			lines = lines.Where(line => !IsManagedTrustIgnoreEntry(line)).ToList();

			if (!allowSharingTrustsInRepositories)
			{
				if (lines.Count > 0 && !string.IsNullOrWhiteSpace(lines[lines.Count - 1]))
				{
					lines.Add(string.Empty);
				}

				lines.AddRange(ManagedTrustIgnoreEntries);
			}

			if (originalCount == lines.Count && File.ReadAllLines(gitIgnorePath).SequenceEqual(lines))
			{
				return false;
			}

			File.WriteAllLines(gitIgnorePath, lines);
			return true;
		}

		private static bool IsManagedTrustIgnoreEntry(string line)
		{
			if (line == null)
			{
				return false;
			}

			var trimmed = line.Trim();

			if (string.IsNullOrWhiteSpace(trimmed))
			{
				return false;
			}

			return ManagedTrustIgnoreEntries.Any(entry => string.Equals(trimmed, entry, StringComparison.OrdinalIgnoreCase));
		}
	}
}
