using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Helper class that contains logic for managing package trusts.
	/// </summary>
	public sealed class ManagePackageTrustsHelper
	{
		private readonly TrustStoreService trustStoreService;

		/// <summary>
		/// Gets the solution path.
		/// </summary>
		public string SolutionPath { get; }

		/// <summary>
		/// Gets the default project path.
		/// </summary>
		public string ProjectPath { get; }

		/// <summary>
		/// Gets the collection of project options.
		/// </summary>
		public ObservableCollection<SolutionProjectOptionViewModel> ProjectOptions { get; } = new();

		/// <summary>
		/// Gets the collection of trusted packages.
		/// </summary>
		public ObservableCollection<PackageTrustItem> TrustedPackages { get; } = new();

		/// <summary>
		/// Gets the active trust store path.
		/// </summary>
		public string TrustStorePath { get; private set; } = string.Empty;

		/// <summary>
		/// Gets a value indicating whether there are unsaved changes.
		/// </summary>
		public bool HasChanges { get; private set; }

		/// <summary>
		/// Gets a value indicating whether any trust entry has been moved to another scope.
		/// </summary>
		public bool HasMovedTrust { get; private set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="ManagePackageTrustsHelper"/> class.
		/// </summary>
		/// <param name="solutionPath">The solution path.</param>
		/// <param name="projectPath">The project path.</param>
		/// <param name="trustStoreService">The trust store service.</param>
		public ManagePackageTrustsHelper(string solutionPath, string projectPath, TrustStoreService? trustStoreService = null)
		{
			this.SolutionPath      = solutionPath ?? string.Empty;
			this.ProjectPath       = projectPath ?? string.Empty;
			this.trustStoreService = trustStoreService ?? new TrustStoreService();
		}

		/// <summary>
		/// Initializes the project options list.
		/// </summary>
		/// <param name="loadedProjectPaths">List of loaded project paths.</param>
		public void InitializeProjectOptions(IEnumerable<string> loadedProjectPaths)
		{
			this.ProjectOptions.Clear();

			if (string.IsNullOrWhiteSpace(this.SolutionPath) || loadedProjectPaths == null)
			{
				return;
			}

			foreach (var loadedPath in loadedProjectPaths.Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.OrdinalIgnoreCase))
			{
				this.ProjectOptions.Add(new SolutionProjectOptionViewModel
				{
					Name = Path.GetFileNameWithoutExtension(loadedPath),
					Path = loadedPath
				});
			}
		}

		/// <summary>
		/// Resolves and loads trusted packages for a given scope and selected project path.
		/// </summary>
		/// <param name="scope">The trust scope.</param>
		/// <param name="selectedProjectPath">The selected project path for project scope.</param>
		public void LoadTrustedPackages(TrustScope scope, string selectedProjectPath)
		{
			this.TrustedPackages.Clear();
			this.TrustStorePath = this.ResolveTrustStorePath(scope, selectedProjectPath);

			if (!File.Exists(this.TrustStorePath))
			{
				return;
			}

			var document = this.trustStoreService.Load(this.TrustStorePath);

			if (document?.Decisions == null || document.Decisions.Count == 0)
			{
				return;
			}

			var packageTrusts = document.Decisions
				.Where(d => d.ScopeKind == TrustDecisionScopeKind.Package || string.Equals(d.Scope, "Package", StringComparison.OrdinalIgnoreCase))
				.GroupBy(d => d.AssemblySigner)
				.Select(g =>
				{
					var first   = g.FirstOrDefault();
					var parts   = g.Key.Split('@');
					var name    = parts.Length > 0 ? parts[0] : g.Key;
					var version = parts.Length > 1 ? parts[1] : string.Empty;

					return new PackageTrustItem
					{
						Name    = name,
						Version = version,
						Hash    = first?.SubjectHash ?? string.Empty,
						Reason  = first?.Reason ?? string.Empty,
						Subject = g.Key
					};
				})
				.OrderBy(p => p.Name)
				.ThenBy(p => p.Version)
				.ToList();

			foreach (var trust in packageTrusts)
			{
				this.TrustedPackages.Add(trust);
			}
		}

		/// <summary>
		/// Resolves the file path of the trust store for the specified scope.
		/// </summary>
		/// <param name="scope">The trust scope.</param>
		/// <param name="selectedProjectPath">The selected project path (only applicable for Project scope).</param>
		/// <returns>The path to the trust store file.</returns>
		public string ResolveTrustStorePath(TrustScope scope, string selectedProjectPath)
		{
			if (scope == TrustScope.Project && !string.IsNullOrWhiteSpace(selectedProjectPath))
			{
				return this.trustStoreService.GetProjectTrustPath(selectedProjectPath);
			}

			if (scope == TrustScope.Solution && !string.IsNullOrWhiteSpace(this.SolutionPath))
			{
				return this.trustStoreService.GetSolutionTrustPath(this.SolutionPath);
			}

			return this.trustStoreService.GetDefaultUserTrustPath();
		}

		/// <summary>
		/// Parses a NuGet manifest file to extract ID and Version.
		/// </summary>
		/// <param name="nuspecPath">Path to the nuspec file.</param>
		/// <param name="packageId">Extracted package ID.</param>
		/// <param name="packageVersion">Extracted package version.</param>
		public static void ParseNuspec(string nuspecPath, out string packageId, out string packageVersion)
		{
			var doc      = XDocument.Load(nuspecPath);
			var metadata = doc.Root?.Elements().FirstOrDefault(el => el.Name.LocalName == "metadata");

			packageId      = metadata?.Elements().FirstOrDefault(el => el.Name.LocalName == "id")?.Value ?? Path.GetFileNameWithoutExtension(nuspecPath);
			packageVersion = metadata?.Elements().FirstOrDefault(el => el.Name.LocalName == "version")?.Value ?? "Unknown";
		}

		/// <summary>
		/// Checks whether a package is already trusted in the current list.
		/// </summary>
		/// <param name="packageId">The package ID.</param>
		/// <param name="packageVersion">The package version.</param>
		/// <returns>True if already trusted, false otherwise.</returns>
		public bool IsPackageAlreadyTrusted(string packageId, string packageVersion)
		{
			var subjectKey = $"{packageId}@{packageVersion}".ToLowerInvariant();

			return this.TrustedPackages.Any(p => string.Equals(p.Subject, subjectKey, StringComparison.OrdinalIgnoreCase));
		}

		/// <summary>
		/// Adds a new package trust item to the collection and marks changes.
		/// </summary>
		/// <param name="packageId">The package ID.</param>
		/// <param name="packageVersion">The package version.</param>
		/// <param name="packageHash">The package hash.</param>
		/// <param name="trustReason">The trust reason.</param>
		public void AddTrustedPackage(string packageId, string packageVersion, string packageHash, string trustReason)
		{
			var subjectKey = $"{packageId}@{packageVersion}".ToLowerInvariant();
			var newTrust   = new PackageTrustItem
			{
				Name    = packageId,
				Version = packageVersion,
				Hash    = packageHash,
				Reason  = trustReason,
				Subject = subjectKey
			};

			this.TrustedPackages.Add(newTrust);
			this.HasChanges = true;
		}

		/// <summary>
		/// Removes a package trust item from the collection and marks changes.
		/// </summary>
		/// <param name="item">The package trust item to remove.</param>
		public void RemoveTrustedPackage(PackageTrustItem item)
		{
			if (item == null)
			{
				return;
			}

			this.TrustedPackages.Remove(item);
			this.HasChanges = true;
		}

		/// <summary>
		/// Moves a package trust entry to a target scope.
		/// </summary>
		/// <param name="selectedTrust">The trust entry to move.</param>
		/// <param name="sourceScope">The source scope of the entry.</param>
		/// <param name="targetScope">The target scope to move to.</param>
		/// <param name="selectedProjectPath">The selected project path for source/target scopes.</param>
		/// <param name="targetProjectPath">The target project path (for Project scope).</param>
		/// <param name="userSid">The current user SID.</param>
		public void MoveTrustToScope(
			PackageTrustItem selectedTrust,
			TrustScope sourceScope,
			TrustScope targetScope,
			string selectedProjectPath,
			string targetProjectPath,
			string userSid)
		{
			if (selectedTrust == null)
			{
				return;
			}

			var sourceProjectPath        = sourceScope == TrustScope.Project ? selectedProjectPath : this.ProjectPath;
			var selectedTargetProjectPath = targetScope == TrustScope.Project ? targetProjectPath : this.ProjectPath;
			var sourcePath                = this.ResolveTrustStorePath(sourceScope, sourceProjectPath);
			var targetPath                = this.ResolveTrustStorePath(targetScope, selectedTargetProjectPath);

			if (string.Equals(sourcePath, targetPath, StringComparison.OrdinalIgnoreCase))
			{
				return;
			}

			var sourceStore   = this.trustStoreService.Load(sourcePath);
			var sourceEntries = sourceStore.Decisions
				.Where(d => (d.ScopeKind == TrustDecisionScopeKind.Package || string.Equals(d.Scope, "Package", StringComparison.OrdinalIgnoreCase)) && string.Equals(d.AssemblySigner, selectedTrust.Subject, StringComparison.OrdinalIgnoreCase))
				.ToList();

			if (sourceEntries.Count == 0)
			{
				return;
			}

			var moveReason = $"Moved package trust from {sourceScope} to {targetScope}";

			foreach (var sourceEntry in sourceEntries)
			{
				var movedEntryReason = string.IsNullOrWhiteSpace(sourceEntry.Reason)
					? moveReason
					: $"{sourceEntry.Reason} ({moveReason})";

				this.trustStoreService.AddDecision(targetPath, new TrustDecisionEntry
				{
					DecisionId       = Guid.NewGuid().ToString("N"),
					Scope            = sourceEntry.Scope,
					SubjectHash      = sourceEntry.SubjectHash,
					AssemblySigner   = sourceEntry.AssemblySigner,
					Decision         = sourceEntry.Decision,
					Reason           = movedEntryReason,
					UserSid          = userSid,
					CreatedAtUtc     = DateTimeOffset.UtcNow,
					ExpiresAtUtc     = sourceEntry.ExpiresAtUtc,
					RepositoryRemote = sourceEntry.RepositoryRemote,
					Branch           = sourceEntry.Branch,
					CommitSha        = sourceEntry.CommitSha,
					PolicyProfile    = sourceEntry.PolicyProfile
				});
			}

			this.trustStoreService.RemoveDecisionsBySubject(sourcePath, selectedTrust.Hash, moveReason, userSid);

			this.TrustedPackages.Remove(selectedTrust);
			this.HasMovedTrust = true;
		}

		/// <summary>
		/// Saves all trusted packages in the active scope trust store.
		/// </summary>
		/// <param name="userSid">The current user SID.</param>
		public void Save(string userSid)
		{
			if (!this.HasChanges)
			{
				return;
			}

			var savePath = this.TrustStorePath;

			if (string.IsNullOrWhiteSpace(savePath))
			{
				savePath = this.trustStoreService.GetDefaultUserTrustPath();
			}

			var document = this.trustStoreService.Load(savePath);

			if (document?.Decisions == null)
			{
				document = new TrustStoreDocument { Decisions = new List<TrustDecisionEntry>() };
			}

			var existingPackageTrusts = document.Decisions
				.Where(d => d.ScopeKind == TrustDecisionScopeKind.Package || string.Equals(d.Scope, "Package", StringComparison.OrdinalIgnoreCase))
				.ToList();

			foreach (var existingTrust in existingPackageTrusts)
			{
				document.Decisions.Remove(existingTrust);
			}

			foreach (var trust in this.TrustedPackages)
			{
				var entry = new TrustDecisionEntry
				{
					DecisionId     = Guid.NewGuid().ToString(),
					Scope          = "Package",
					SubjectHash    = trust.Hash,
					AssemblySigner = trust.Subject,
					Decision       = "Trust",
					Reason         = trust.Reason,
					UserSid        = userSid,
					CreatedAtUtc   = DateTimeOffset.UtcNow
				};

				document.Decisions.Add(entry);
			}

			this.trustStoreService.Save(savePath, document);
		}

		/// <summary>
		/// Resets the changes flag.
		/// </summary>
		public void ClearChanges()
		{
			this.HasChanges = false;
		}
	}

	/// <summary>
	/// Represents a trusted NuGet package item.
	/// </summary>
	public sealed class PackageTrustItem
	{
		/// <summary>
		/// Gets or sets the package ID name.
		/// </summary>
		public string Name { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package version.
		/// </summary>
		public string Version { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package directory hash.
		/// </summary>
		public string Hash { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the reasoning or description for trusting the package.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the subject identifier (e.g. packageid@version).
		/// </summary>
		public string Subject { get; set; } = string.Empty;
	}
}
