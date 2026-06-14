using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Helper class that contains logic for managing trusted assemblies.
	/// </summary>
	public sealed class ManageAssemblyTrustsHelper
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
		/// Gets the collection of trusted assemblies.
		/// </summary>
		public ObservableCollection<AssemblyTrustItem> TrustedAssemblies { get; } = new();

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
		/// Initializes a new instance of the <see cref="ManageAssemblyTrustsHelper"/> class.
		/// </summary>
		/// <param name="solutionPath">The solution path.</param>
		/// <param name="projectPath">The project path.</param>
		/// <param name="trustStoreService">The trust store service.</param>
		public ManageAssemblyTrustsHelper(string solutionPath, string projectPath, TrustStoreService? trustStoreService = null)
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
		/// Resolves and loads trusted assemblies for a given scope and selected project path.
		/// </summary>
		/// <param name="scope">The trust scope.</param>
		/// <param name="selectedProjectPath">The selected project path for project scope.</param>
		public void LoadTrustedAssemblies(TrustScope scope, string selectedProjectPath)
		{
			this.TrustedAssemblies.Clear();
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

			var assemblyTrusts = document.Decisions
				.Where(d => d.ScopeKind == TrustDecisionScopeKind.Assembly || string.Equals(d.Scope, "Assembly", StringComparison.OrdinalIgnoreCase))
				.GroupBy(d => d.SubjectHash)
				.Select(g =>
				{
					var signer      = g.Select(item => item.AssemblySigner).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
					var issuer      = g.Select(item => item.AssemblyIssuer).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
					var subjectName = g.Select(item => item.AssemblySubject).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

					if (string.IsNullOrWhiteSpace(signer) && string.IsNullOrWhiteSpace(issuer))
					{
						var name    = ExtractAssemblyName(g.Key);
						var version = ExtractAssemblyVersion(g.Key);
						var dllPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(name, version);

						if (!string.IsNullOrWhiteSpace(dllPath))
						{
							var sig     = new AssemblySignatureService().ReadSignature(dllPath);

							signer      = sig.Signer;
							issuer      = sig.Issuer;
							subjectName = sig.Subject;
						}
					}

					return new AssemblyTrustItem
					{
						Name        = ExtractAssemblyName(g.Key),
						Version     = ExtractAssemblyVersion(g.Key),
						Signer      = signer,
						Issuer      = issuer,
						SubjectName = subjectName,
						Reason      = g.FirstOrDefault()?.Reason ?? string.Empty,
						Subject     = g.Key
					};
				})
				.OrderBy(a => a.Name)
				.ThenBy(a => a.Version)
				.ToList();

			foreach (var trust in assemblyTrusts)
			{
				this.TrustedAssemblies.Add(trust);
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
		/// Extracts the assembly name from the subject identifier (name@version format).
		/// </summary>
		/// <param name="subject">The subject identifier.</param>
		/// <returns>The assembly name.</returns>
		public static string ExtractAssemblyName(string subject)
		{
			if (subject == null)
			{
				return string.Empty;
			}

			var parts = subject.Split('@');

			return parts.Length > 0 ? parts[0] : subject;
		}

		/// <summary>
		/// Extracts the assembly version from the subject identifier (name@version format).
		/// </summary>
		/// <param name="subject">The subject identifier.</param>
		/// <returns>The assembly version.</returns>
		public static string ExtractAssemblyVersion(string subject)
		{
			if (subject == null)
			{
				return string.Empty;
			}

			var parts = subject.Split('@');

			return parts.Length > 1 ? parts[1] : string.Empty;
		}

		/// <summary>
		/// Adds a new assembly trust item to the collection and marks changes.
		/// </summary>
		/// <param name="name">The assembly name.</param>
		/// <param name="version">The assembly version.</param>
		/// <param name="signer">The assembly signer.</param>
		/// <param name="issuer">The certificate issuer.</param>
		/// <param name="subjectName">The certificate subject name.</param>
		/// <param name="reason">The trust reason.</param>
		public void AddTrustedAssembly(string name, string version, string signer, string issuer, string subjectName, string reason)
		{
			var newTrust = new AssemblyTrustItem
			{
				Name        = name,
				Version     = version,
				Signer      = signer,
				Issuer      = issuer,
				SubjectName = subjectName,
				Reason      = reason,
				Subject     = $"{name}@{version}"
			};

			this.TrustedAssemblies.Add(newTrust);
			this.HasChanges = true;
		}

		/// <summary>
		/// Removes an assembly trust item from the collection and marks changes.
		/// </summary>
		/// <param name="item">The assembly trust item to remove.</param>
		public void RemoveTrustedAssembly(AssemblyTrustItem item)
		{
			if (item == null)
			{
				return;
			}

			this.TrustedAssemblies.Remove(item);
			this.HasChanges = true;
		}

		/// <summary>
		/// Moves an assembly trust entry to a target scope.
		/// </summary>
		/// <param name="selectedTrust">The trust entry to move.</param>
		/// <param name="sourceScope">The source scope of the entry.</param>
		/// <param name="targetScope">The target scope to move to.</param>
		/// <param name="selectedProjectPath">The selected project path for source/target scopes.</param>
		/// <param name="targetProjectPath">The target project path (for Project scope).</param>
		/// <param name="userSid">The current user SID.</param>
		public void MoveTrustToScope(
			AssemblyTrustItem selectedTrust,
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
				.Where(d => (d.ScopeKind == TrustDecisionScopeKind.Assembly || string.Equals(d.Scope, "Assembly", StringComparison.OrdinalIgnoreCase)) && string.Equals(d.SubjectHash, selectedTrust.Subject, StringComparison.OrdinalIgnoreCase))
				.ToList();

			if (sourceEntries.Count == 0)
			{
				return;
			}

			var moveReason = $"Moved assembly trust from {sourceScope} to {targetScope}";

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

			this.trustStoreService.RemoveDecisionsBySubject(sourcePath, selectedTrust.Subject, moveReason, userSid);

			this.TrustedAssemblies.Remove(selectedTrust);
			this.HasMovedTrust = true;
		}

		/// <summary>
		/// Saves all trusted assemblies in the active scope trust store.
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

			var existingAssemblyTrusts = document.Decisions
				.Where(d => d.ScopeKind == TrustDecisionScopeKind.Assembly || string.Equals(d.Scope, "Assembly", StringComparison.OrdinalIgnoreCase))
				.ToList();

			foreach (var existingTrust in existingAssemblyTrusts)
			{
				document.Decisions.Remove(existingTrust);
			}

			foreach (var trust in this.TrustedAssemblies)
			{
				var entry = new TrustDecisionEntry
				{
					DecisionId      = Guid.NewGuid().ToString(),
					Scope           = "Assembly",
					SubjectHash     = trust.Subject,
					AssemblySigner  = trust.Signer,
					AssemblyIssuer  = trust.Issuer,
					AssemblySubject = trust.SubjectName,
					Decision        = "Trust",
					Reason          = trust.Reason,
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
	/// Represents a single trusted assembly item in the list.
	/// </summary>
	public sealed class AssemblyTrustItem
	{
		/// <summary>
		/// Gets or sets the assembly name.
		/// </summary>
		public string Name { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly version.
		/// </summary>
		public string Version { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly signer.
		/// </summary>
		public string Signer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate issuer.
		/// </summary>
		public string Issuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate subject.
		/// </summary>
		public string SubjectName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the trust reason.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the subject identifier (name@version).
		/// </summary>
		public string Subject { get; set; } = string.Empty;
	}
}
