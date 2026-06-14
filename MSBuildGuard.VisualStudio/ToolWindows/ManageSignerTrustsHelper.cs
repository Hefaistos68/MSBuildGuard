using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Helper class that contains logic for managing trusted certificate signers.
	/// </summary>
	public sealed class ManageSignerTrustsHelper
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
		/// Gets the collection of trusted signers.
		/// </summary>
		public ObservableCollection<SignerTrustItem> TrustedSigners { get; } = new();

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
		/// Initializes a new instance of the <see cref="ManageSignerTrustsHelper"/> class.
		/// </summary>
		/// <param name="solutionPath">The solution path.</param>
		/// <param name="projectPath">The project path.</param>
		/// <param name="trustStoreService">The trust store service.</param>
		public ManageSignerTrustsHelper(string solutionPath, string projectPath, TrustStoreService? trustStoreService = null)
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
		/// Resolves and loads trusted signers for a given scope and selected project path.
		/// </summary>
		/// <param name="scope">The trust scope.</param>
		/// <param name="selectedProjectPath">The selected project path for project scope.</param>
		public void LoadTrustedSigners(TrustScope scope, string selectedProjectPath)
		{
			this.TrustedSigners.Clear();
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

			var signerTrusts = document.Decisions
				.Where(d => d.ScopeKind == TrustDecisionScopeKind.Signer || string.Equals(d.Scope, "Signer", StringComparison.OrdinalIgnoreCase))
				.GroupBy(d => d.SubjectHash, StringComparer.OrdinalIgnoreCase)
				.Select(g =>
				{
					var first = g.OrderByDescending(x => x.CreatedAtUtc).First();

					return new SignerTrustItem
					{
						SubjectDn        = first.SubjectHash,
						SignerName       = first.AssemblySigner,
						Issuer           = first.AssemblyIssuer,
						Reason           = first.Reason,
						CreatedAtDisplay = first.CreatedAtUtc.LocalDateTime.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture)
					};
				})
				.OrderBy(s => s.SignerName)
				.ToList();

			foreach (var item in signerTrusts)
			{
				this.TrustedSigners.Add(item);
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
		/// Removes a signer trust item from the collection and marks changes.
		/// </summary>
		/// <param name="item">The signer trust item to remove.</param>
		public void RemoveTrustedSigner(SignerTrustItem item)
		{
			if (item == null)
			{
				return;
			}

			this.TrustedSigners.Remove(item);
			this.HasChanges = true;
		}

		/// <summary>
		/// Moves a signer trust entry to a target scope.
		/// </summary>
		/// <param name="selectedTrust">The trust entry to move.</param>
		/// <param name="sourceScope">The source scope of the entry.</param>
		/// <param name="targetScope">The target scope to move to.</param>
		/// <param name="selectedProjectPath">The selected project path for source/target scopes.</param>
		/// <param name="targetProjectPath">The target project path (for Project scope).</param>
		/// <param name="userSid">The current user SID.</param>
		public void MoveTrustToScope(
			SignerTrustItem selectedTrust,
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
				.Where(d => (d.ScopeKind == TrustDecisionScopeKind.Signer || string.Equals(d.Scope, "Signer", StringComparison.OrdinalIgnoreCase)) && string.Equals(d.SubjectHash, selectedTrust.SubjectDn, StringComparison.OrdinalIgnoreCase))
				.ToList();

			if (sourceEntries.Count == 0)
			{
				return;
			}

			var moveReason = $"Moved signer trust from {sourceScope} to {targetScope}";

			foreach (var sourceEntry in sourceEntries)
			{
				var movedEntryReason = string.IsNullOrWhiteSpace(sourceEntry.Reason)
					? moveReason
					: $"{sourceEntry.Reason} ({moveReason})";

				this.trustStoreService.AddDecision(targetPath, new TrustDecisionEntry
				{
					DecisionId           = Guid.NewGuid().ToString("N"),
					Scope                = sourceEntry.Scope,
					SubjectHash          = sourceEntry.SubjectHash,
					AssemblySigner       = sourceEntry.AssemblySigner,
					AssemblyIssuer       = sourceEntry.AssemblyIssuer,
					AssemblySubject      = sourceEntry.AssemblySubject,
					AssemblyThumbprint   = sourceEntry.AssemblyThumbprint,
					AssemblySerialNumber = sourceEntry.AssemblySerialNumber,
					Decision             = sourceEntry.Decision,
					Reason               = movedEntryReason,
					UserSid              = userSid,
					CreatedAtUtc         = DateTimeOffset.UtcNow,
					ExpiresAtUtc         = sourceEntry.ExpiresAtUtc,
					RepositoryRemote     = sourceEntry.RepositoryRemote,
					Branch               = sourceEntry.Branch,
					CommitSha            = sourceEntry.CommitSha,
					PolicyProfile        = sourceEntry.PolicyProfile
				});
			}

			this.trustStoreService.RemoveDecisionsBySubject(sourcePath, selectedTrust.SubjectDn, moveReason, userSid);

			this.TrustedSigners.Remove(selectedTrust);
			this.HasMovedTrust = true;
		}

		/// <summary>
		/// Saves all trusted signers in the active scope trust store.
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

			var existingSignerTrusts = document.Decisions
				.Where(d => d.ScopeKind == TrustDecisionScopeKind.Signer || string.Equals(d.Scope, "Signer", StringComparison.OrdinalIgnoreCase))
				.ToList();

			foreach (var entry in existingSignerTrusts)
			{
				document.Decisions.Remove(entry);
			}

			foreach (var item in this.TrustedSigners)
			{
				var entry = new TrustDecisionEntry
				{
					DecisionId      = Guid.NewGuid().ToString(),
					Scope           = "Signer",
					SubjectHash     = item.SubjectDn,
					AssemblySigner  = item.SignerName,
					AssemblyIssuer  = item.Issuer,
					AssemblySubject = item.SubjectDn,
					Decision        = "Trust",
					Reason          = item.Reason,
					UserSid         = userSid,
					CreatedAtUtc    = DateTimeOffset.UtcNow
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
	/// Represents a single trusted signer entry in the list.
	/// </summary>
	public sealed class SignerTrustItem
	{
		/// <summary>
		/// Gets or sets the certificate Subject DN used as the canonical trust key.
		/// </summary>
		public string SubjectDn { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the human-readable signer display name.
		/// </summary>
		public string SignerName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate issuer.
		/// </summary>
		public string Issuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the reason the signer was trusted.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the formatted trust creation date for display.
		/// </summary>
		public string CreatedAtDisplay { get; set; } = string.Empty;
	}
}
