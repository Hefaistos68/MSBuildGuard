using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Services;

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

			this.TargetPath = report.Target.TargetPath;

			var trustStoreService = new TrustStoreService();
			var trustStore = trustStoreService.Load(trustStoreService.GetDefaultUserTrustPath());
			var hasSignerTrusts = trustStore.Decisions.Any(d => d.ScopeKind == TrustDecisionScopeKind.Signer);
			var signatureCache = new Dictionary<string, AssemblySignatureService>(StringComparer.OrdinalIgnoreCase);
			var activeRiskScore = 0;
			var trustedRiskScore = 0;
			var findings = new List<FindingRow>();

			foreach (var finding in report.Findings)
			{
				var fileRecord = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));
				var isTrusted = !string.IsNullOrWhiteSpace(finding.Fingerprint) &&
					fileRecord != null &&
					trustStoreService.IsFindingApproved(trustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile);

				var isApprovedByAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion) &&
					trustStoreService.IsFindingApprovedByAssembly(trustStore, finding.PackageId, finding.PackageVersion);

				var isApprovedBySigner = false;

				if (hasSignerTrusts && !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					var cacheKey = $"{finding.PackageId}@{finding.PackageVersion}";

					if (!signatureCache.TryGetValue(cacheKey, out var sigService))
					{
						sigService = new AssemblySignatureService();
						signatureCache[cacheKey] = sigService;
					}

					var dllPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);
					var sig = sigService.ReadSignature(dllPath);

					if (sig.IsSignatureValid && (!string.IsNullOrWhiteSpace(sig.Thumbprint) || !string.IsNullOrWhiteSpace(sig.Subject)))
					{
						isApprovedBySigner = trustStoreService.IsSignerTrusted(trustStore, sig.Thumbprint, sig.Subject, sig.Issuer, sig.SerialNumber);
					}
				}

				var isEffectivelyTrusted = isTrusted || isApprovedByAssembly || isApprovedBySigner;
				var risk = GetSeverityRisk(finding.Severity);

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

			this.RiskScore = activeRiskScore;
			this.TrustedRiskScore = trustedRiskScore;
			this.RecommendedAction = MapRecommendedAction(activeRiskScore).ToString();
			this.Findings = findings;
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
