using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Services;
using Microsoft.VisualStudio.Shell;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// View model for the build block confirmation dialog.
	/// </summary>
	public sealed class BuildBlockDialogViewModel
	{
		/// <summary>
		/// Represents a single actionable finding row in the dialog grid.
		/// </summary>
		public sealed class FindingRow
		{
			/// <summary>Gets the rule identifier.</summary>
			public string RuleId { get; set; } = string.Empty;

			/// <summary>Gets the finding title.</summary>
			public string Title { get; set; } = string.Empty;

			/// <summary>Gets the severity label.</summary>
			public string Severity { get; set; } = string.Empty;

			/// <summary>Gets the required policy action label.</summary>
			public string Action { get; set; } = string.Empty;

			/// <summary>Gets the short display path of the affected file.</summary>
			public string FilePath { get; set; } = string.Empty;
		}

		/// <summary>
		/// Gets the scan target path.
		/// </summary>
		public string TargetPath { get; }

		/// <summary>
		/// Gets the redacted scan target path for UI display.
		/// </summary>
		public string TargetPathDisplay
		{
			get
			{
				return PathRedactionService.RedactPath(this.TargetPath);
			}
		}

		/// <summary>
		/// Gets the aggregate active risk score.
		/// </summary>
		public int RiskScore { get; }

		/// <summary>
		/// Gets the aggregate trusted risk score.
		/// </summary>
		public int TrustedRiskScore { get; }

		/// <summary>
		/// Gets the recommended action label.
		/// </summary>
		public string RecommendedAction { get; }

		/// <summary>
		/// Gets the risk level string representing severity.
		/// </summary>
		public string RiskLevel
		{
			get
			{
				if (this.RiskScore >= 100) return "High";
				if (this.RiskScore >= 20) return "Medium";
				return "Low";
			}
		}

		/// <summary>
		/// Gets the list of actionable findings to display.
		/// </summary>
		public IReadOnlyList<FindingRow> Findings { get; }

		/// <summary>
		/// Initializes a new instance of the <see cref="BuildBlockDialogViewModel"/> class from a scan report.
		/// </summary>
		/// <param name="report">The scan report that triggered the build block.</param>
		public BuildBlockDialogViewModel(ScanReport report)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			ThreadHelper.ThrowIfNotOnUIThread();

			var solutionPath = SolutionDiscoveryService.GetOpenSolutionPath();
			var model        = new BuildBlockDialogViewModel(report, solutionPath);

			this.TargetPath        = model.TargetPath;
			this.RiskScore         = model.RiskScore;
			this.TrustedRiskScore  = model.TrustedRiskScore;
			this.RecommendedAction = model.RecommendedAction;
			this.Findings          = model.Findings;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="BuildBlockDialogViewModel"/> class with an explicit solution path, making it safe for background thread execution.
		/// </summary>
		/// <param name="report">The scan report.</param>
		/// <param name="solutionPath">The solution path.</param>
		public BuildBlockDialogViewModel(ScanReport report, string? solutionPath)
			: this(report, solutionPath, null)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="BuildBlockDialogViewModel"/> class with an explicit solution path and optional project path filter.
		/// </summary>
		/// <param name="report">The scan report.</param>
		/// <param name="solutionPath">The solution path.</param>
		/// <param name="projectPathFilter">The project path filter.</param>
		public BuildBlockDialogViewModel(ScanReport report, string? solutionPath, string? projectPathFilter)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			this.TargetPath = !string.IsNullOrWhiteSpace(projectPathFilter) ? projectPathFilter! : report.Target.TargetPath;

			var trustStoreService      = new TrustStoreService();
			var isProject              = !string.IsNullOrWhiteSpace(projectPathFilter) ||
				(report.Target.TargetKind == TargetKind.File &&
				 (report.Target.TargetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
				  report.Target.TargetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase) ||
				  report.Target.TargetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
				  report.Target.TargetPath.EndsWith(".proj", StringComparison.OrdinalIgnoreCase)));
			var currentProjectPath     = !string.IsNullOrWhiteSpace(projectPathFilter) ? projectPathFilter : (isProject ? report.Target.TargetPath : null);
			var trustStore             = trustStoreService.LoadMergedTrustStore(trustStoreService.GetDefaultUserTrustPath(), solutionPath, currentProjectPath);
			var signatureCache         = new Dictionary<string, AssemblySignatureService>(StringComparer.OrdinalIgnoreCase);
			var projectTrustStoreCache = new Dictionary<string, TrustStoreDocument>(StringComparer.OrdinalIgnoreCase);
			var activeRiskScore        = 0;
			var trustedRiskScore       = 0;
			var findings               = new List<FindingRow>();

			foreach (var finding in report.Findings)
			{
				if (!string.IsNullOrWhiteSpace(projectPathFilter))
				{
					if (!IsFindingForProject(finding, projectPathFilter!, solutionPath))
					{
						continue;
					}
				}

				if (string.IsNullOrWhiteSpace(finding.PackageId) && TryInferPackageFromPath(finding.FilePath, out var inferredId, out var inferredVersion))
				{
					finding.PackageId      = inferredId;
					finding.PackageVersion = inferredVersion;
				}

				var fileRecord           = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));
				var projectTrustStore    = GetProjectTrustStore(solutionPath, finding.IntroducedViaProject, trustStoreService, projectTrustStoreCache);
				var isTrusted            = !string.IsNullOrWhiteSpace(finding.Fingerprint) &&
					fileRecord != null &&
					(trustStoreService.IsFindingApproved(trustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile) ||
					 (projectTrustStore != null && trustStoreService.IsFindingApproved(projectTrustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile)));

				var isApprovedByAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion) &&
					(trustStoreService.IsFindingApprovedByAssembly(trustStore, finding.PackageId, finding.PackageVersion) ||
					 (projectTrustStore != null && trustStoreService.IsFindingApprovedByAssembly(projectTrustStore, finding.PackageId, finding.PackageVersion)));

				var isApprovedBySigner   = IsAssemblyApproved(finding, trustStoreService, trustStore, projectTrustStore, signatureCache);

				var isApprovedByPackage  = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion) &&
					(trustStoreService.IsFindingApprovedByPackage(trustStore, finding.PackageId, finding.PackageVersion) ||
					 (projectTrustStore != null && trustStoreService.IsFindingApprovedByPackage(projectTrustStore, finding.PackageId, finding.PackageVersion)));

				var isEffectivelyTrusted = isTrusted || isApprovedByAssembly || isApprovedBySigner || isApprovedByPackage;
				var risk                 = GetSeverityRisk(finding.Severity);

				if (isEffectivelyTrusted)
				{
					trustedRiskScore += risk;

					continue;
				}

				activeRiskScore += risk;

				if (finding.PolicyEvaluatedAction == PolicyAction.Allow)
				{
					continue;
				}

				findings.Add(new FindingRow
				{
					RuleId   = finding.Id,
					Title    = finding.Title,
					Severity = finding.Severity.ToString(),
					Action   = finding.PolicyEvaluatedAction.ToString(),
					FilePath = string.IsNullOrWhiteSpace(finding.FilePath)
						? string.Empty
						: Path.GetFileName(finding.FilePath)
				});
			}

			this.RiskScore         = activeRiskScore;
			this.TrustedRiskScore  = trustedRiskScore;
			this.RecommendedAction = MapRecommendedAction(activeRiskScore).ToString();
			this.Findings          = findings;
		}

		/// <summary>
		/// Determines whether a finding is associated with a specific project.
		/// </summary>
		/// <param name="finding">The finding to evaluate.</param>
		/// <param name="projectPath">The project path to match against.</param>
		/// <param name="solutionPath">The solution path.</param>
		/// <returns>A value indicating whether the finding is associated with the project.</returns>
		private static bool IsFindingForProject(Finding finding, string projectPath, string? solutionPath)
		{
			if (string.IsNullOrWhiteSpace(projectPath))
			{
				return false;
			}

			if (!string.IsNullOrWhiteSpace(finding.IntroducedViaProject))
			{
				var absoluteFindingProjectPath = Path.IsPathRooted(finding.IntroducedViaProject)
					? Path.GetFullPath(finding.IntroducedViaProject)
					: Path.GetFullPath(Path.Combine(Path.GetDirectoryName(solutionPath) ?? string.Empty, finding.IntroducedViaProject));

				if (string.Equals(absoluteFindingProjectPath, projectPath, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}

			if (!string.IsNullOrWhiteSpace(finding.FilePath))
			{
				var absoluteFilePath = Path.IsPathRooted(finding.FilePath)
					? Path.GetFullPath(finding.FilePath)
					: Path.GetFullPath(Path.Combine(Path.GetDirectoryName(solutionPath) ?? string.Empty, finding.FilePath));

				if (string.Equals(absoluteFilePath, projectPath, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}

				var projectDirectory = Path.GetDirectoryName(projectPath);

				if (!string.IsNullOrWhiteSpace(projectDirectory))
				{
					var projectDirNormalized = projectDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

					if (absoluteFilePath.StartsWith(projectDirNormalized, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}
				}
			}

			return false;
		}

		/// <summary>
		/// Resolves the project-level trust store if available, loading it via the cache.
		/// </summary>
		/// <param name="solutionPath">The path to the open solution.</param>
		/// <param name="findingProjectPath">The project path associated with the finding.</param>
		/// <param name="trustStoreService">The trust store service.</param>
		/// <param name="cache">The dictionary cache of project trust stores.</param>
		/// <returns>The loaded project trust store document, or null.</returns>
		private static TrustStoreDocument? GetProjectTrustStore(
			string? solutionPath,
			string? findingProjectPath,
			TrustStoreService trustStoreService,
			Dictionary<string, TrustStoreDocument> cache)
		{
			if (string.IsNullOrWhiteSpace(findingProjectPath) || string.IsNullOrWhiteSpace(solutionPath))
			{
				return null;
			}

			var absoluteFindingProjectPath = Path.IsPathRooted(findingProjectPath)
				? Path.GetFullPath(findingProjectPath)
				: Path.GetFullPath(Path.Combine(Path.GetDirectoryName(solutionPath) ?? string.Empty, findingProjectPath));

			if (!cache.TryGetValue(absoluteFindingProjectPath, out var projectTrustStore))
			{
				projectTrustStore = trustStoreService.Load(trustStoreService.GetProjectTrustPath(absoluteFindingProjectPath));
				cache[absoluteFindingProjectPath] = projectTrustStore;
			}

			return projectTrustStore;
		}

		/// <summary>
		/// Evaluates assembly signature trusts on user, solution, and project trust stores.
		/// </summary>
		/// <param name="finding">The finding to evaluate.</param>
		/// <param name="trustStoreService">The trust store service.</param>
		/// <param name="trustStore">The merged User + Solution trust store.</param>
		/// <param name="projectTrustStore">The project trust store, if any.</param>
		/// <param name="signatureCache">The signature service cache.</param>
		/// <returns>A value indicating whether the assembly signer is trusted.</returns>
		private static bool IsAssemblyApproved(
			Finding finding,
			TrustStoreService trustStoreService,
			TrustStoreDocument trustStore,
			TrustStoreDocument? projectTrustStore,
			Dictionary<string, AssemblySignatureService> signatureCache)
		{
			if (string.IsNullOrWhiteSpace(finding.PackageId) || string.IsNullOrWhiteSpace(finding.PackageVersion))
			{
				return false;
			}

			var hasSignerTrusts        = trustStore.Decisions.Any(d => d.ScopeKind == TrustDecisionScopeKind.Signer);
			var hasProjectSignerTrusts = projectTrustStore != null && projectTrustStore.Decisions.Any(d => d.ScopeKind == TrustDecisionScopeKind.Signer);

			if (!hasSignerTrusts && !hasProjectSignerTrusts)
			{
				return false;
			}

			var cacheKey   = $"{finding.PackageId}@{finding.PackageVersion}";
			var sigService = (AssemblySignatureService?)null;

			if (!signatureCache.TryGetValue(cacheKey, out sigService))
			{
				sigService = new AssemblySignatureService();
				signatureCache[cacheKey] = sigService;
			}

			var dllPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);
			var sig     = sigService.ReadSignature(dllPath);

			if (sig.IsSignatureValid && (!string.IsNullOrWhiteSpace(sig.Thumbprint) || !string.IsNullOrWhiteSpace(sig.Subject)))
			{
				return trustStoreService.IsSignerTrusted(trustStore, sig.Thumbprint, sig.Subject, sig.Issuer, sig.SerialNumber) ||
					(projectTrustStore != null && trustStoreService.IsSignerTrusted(projectTrustStore, sig.Thumbprint, sig.Subject, sig.Issuer, sig.SerialNumber));
			}

			return false;
		}

		private static bool TryInferPackageFromPath(string filePath, out string packageId, out string packageVersion)
		{
			packageId      = string.Empty;
			packageVersion = string.Empty;

			if (string.IsNullOrWhiteSpace(filePath))
			{
				return false;
			}

			var directory = Path.GetDirectoryName(filePath);

			var candidate = directory;

			for (var depth = 0; depth < 6 && !string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate); depth++)
			{
				if (Directory.Exists(Path.Combine(candidate, "lib")) ||
					Directory.Exists(Path.Combine(candidate, "tools")) ||
					Directory.Exists(Path.Combine(candidate, "runtimes")))
				{
					var version = Path.GetFileName(candidate);

					var parentDir = Path.GetDirectoryName(candidate);

					if (!string.IsNullOrWhiteSpace(version) && !string.IsNullOrWhiteSpace(parentDir))
					{
						var id = Path.GetFileName(parentDir);

						if (!string.IsNullOrWhiteSpace(id))
						{
							packageId      = id;
							packageVersion = version;

							return true;
						}
					}

					break;
				}

				candidate = Path.GetDirectoryName(candidate);
			}

			return false;
		}

		private static int GetSeverityRisk(FindingSeverity severity)
		{
			switch (severity)
			{
				case FindingSeverity.None:
				case FindingSeverity.Info:
					return 0;
				case FindingSeverity.Low:
					return 5;
				case FindingSeverity.Medium:
					return 20;
				case FindingSeverity.High:
					return 50;
				case FindingSeverity.Critical:
					return 100;
				default:
					return 0;
			}
		}

		private static MSBuildGuard.Core.RecommendedAction MapRecommendedAction(int riskScore)
		{
			if (riskScore >= 100)
			{
				return MSBuildGuard.Core.RecommendedAction.Block;
			}

			if (riskScore >= 50)
			{
				return MSBuildGuard.Core.RecommendedAction.RequireApproval;
			}

			if (riskScore >= 20)
			{
				return MSBuildGuard.Core.RecommendedAction.Warn;
			}

			return MSBuildGuard.Core.RecommendedAction.Allow;
		}
	}
}
