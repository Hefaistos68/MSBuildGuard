using System.Text;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Extensions;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.Models
{
	/// <summary>
	/// Represents a finding row in the tool window grid.
	/// </summary>
	public sealed class FindingViewModel
	{
		/// <summary>
		/// Gets or sets the finding severity.
		/// </summary>
		public string Severity { get; set; } = string.Empty;

		/// <summary>
		/// Gets the shield icon path associated with the current severity.
		/// </summary>
		public string SeverityIconPath
		{
			get
			{
				if (!System.Enum.TryParse<FindingSeverity>(this.Severity, out var severity))
				{
					return "/MSBuildguard.VisualStudio;component/ToolWindows/AppShieldGreen-24x24.png";
				}

				switch (severity)
				{
					case FindingSeverity.Low:
						return "/MSBuildguard.VisualStudio;component/ToolWindows/AppShieldGreen-24x24.png";
					case FindingSeverity.Medium:
						return "/MSBuildguard.VisualStudio;component/Resources/ProjectSecurityShield.png";
					case FindingSeverity.High:
						return "/MSBuildguard.VisualStudio;component/Resources/ProjectSecurityShieldOrange.png";
					case FindingSeverity.Critical:
						return "/MSBuildguard.VisualStudio;component/Resources/ProjectSecurityShieldRed.png";
					default:
						return "/MSBuildguard.VisualStudio;component/ToolWindows/AppShieldGreen-24x24.png";
				}
			}
		}

		/// <summary>
		/// Gets or sets the rule identifier.
		/// </summary>
		public string RuleId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the finding title.
		/// </summary>
		public string Title { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the source file path.
		/// </summary>
		public string FilePath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package asset path when this finding originates from a NuGet package asset.
		/// </summary>
		public string NuGetAssetPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package identifier for package-sourced findings.
		/// </summary>
		public string PackageId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package version for package-sourced findings.
		/// </summary>
		public string PackageVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the project path that introduced this finding (populated for package-sourced findings).
		/// </summary>
		public string IntroducedViaProject { get; set; } = string.Empty;

		/// <summary>
		/// Gets the source file path formatted for compact grid display.
		/// </summary>
		public string FilePathDisplay
		{
			get
			{
				return PathRedactionService.RedactPath(this.FilePath).TrimMiddlePath(56);
			}
		}

		/// <summary>
		/// Gets or sets the source line.
		/// </summary>
		public int Line { get; set; }

		/// <summary>
		/// Gets or sets the policy action.
		/// </summary>
		public string PolicyAction { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the finding fingerprint.
		/// </summary>
		public string Fingerprint { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether the finding is trusted.
		/// </summary>
		public bool IsTrusted { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether a matching trust-store entry exists for this finding.
		/// </summary>
		public bool IsInTrustStore { get; set; }

		/// <summary>
		/// Gets a value indicating whether the finding can be added to the trust store.
		/// </summary>
		public bool CanTrust
		{
			get
			{
				return !string.Equals(this.RuleId, "MBG000", System.StringComparison.OrdinalIgnoreCase) &&
					!string.IsNullOrWhiteSpace(this.Fingerprint) &&
					!this.IsInTrustStore;
			}
		}

		/// <summary>
		/// Gets a value indicating whether the finding can be removed from the trust store.
		/// </summary>
		public bool CanRemoveTrust
		{
			get
			{
				return !string.Equals(this.RuleId, "MBG000", System.StringComparison.OrdinalIgnoreCase) &&
					!string.IsNullOrWhiteSpace(this.Fingerprint) &&
					this.IsInTrustStore;
			}
		}

		/// <summary>
		/// Gets or sets the owning assembly name and version for this finding (populated for package-sourced findings).
		/// </summary>
		public string OwningAssembly { get; set; } = string.Empty;

		/// <summary>
		/// Gets a value indicating whether this finding can be trusted by its owning assembly.
		/// </summary>
		public bool CanTrustAssembly
		{
			get
			{
				return !string.Equals(this.RuleId, "MBG000", System.StringComparison.OrdinalIgnoreCase) &&
					!string.IsNullOrWhiteSpace(this.OwningAssembly);
			}
		}

		/// <summary>
		/// Gets a value indicating whether this finding's owning assembly can be untrusted.
		/// </summary>
		public bool CanUntrustAssembly
		{
			get
			{
				return !string.Equals(this.RuleId, "MBG000", System.StringComparison.OrdinalIgnoreCase) &&
					!string.IsNullOrWhiteSpace(this.OwningAssembly);
			}
		}

		/// <summary>
		/// Gets or sets a value indicating whether the finding is new relative to baseline.
		/// </summary>
		public bool IsNewComparedWithBaseline { get; set; }

		/// <summary>
		/// Gets the full reasoning text explaining what caused this finding and its current state.
		/// </summary>
		public string Reasoning { get; set; } = string.Empty;

		/// <summary>
		/// Builds the reasoning text from the provided <see cref="Finding"/> and trust state.
		/// </summary>
		/// <param name="finding">The source finding.</param>
		/// <param name="isTrusted">A value indicating whether the finding is currently trusted by the trust store.</param>
		/// <returns>A human-readable reasoning string.</returns>
		public static string BuildReasoning(Finding finding, bool isTrusted)
		{
			var sb = new StringBuilder();

			sb.AppendLine($"Rule: {finding.Id} — {finding.Title}");
			sb.AppendLine($"Severity: {finding.Severity}  |  Confidence: {finding.Confidence}");
			sb.AppendLine();

			if (!string.IsNullOrWhiteSpace(finding.Description))
			{
				sb.AppendLine("Description:");
				sb.AppendLine(finding.Description);
				sb.AppendLine();
			}

			sb.AppendLine();

			if (string.Equals(finding.Id, "MBG000", System.StringComparison.OrdinalIgnoreCase))
			{
				sb.AppendLine("Trust status: No issues were detected for this target.");
			}
			else if (isTrusted)
			{
				sb.AppendLine("Trust status: This finding is trusted (fingerprint approved in trust store).");
			}
			else
			{
				sb.AppendLine("Trust status: Not trusted.");
			}

			if (!string.IsNullOrWhiteSpace(finding.Recommendation))
			{
				sb.AppendLine();
				sb.AppendLine("Recommendation:");
				sb.AppendLine(finding.Recommendation);
			}

			if (!string.IsNullOrWhiteSpace(finding.Evidence))
			{
				sb.AppendLine();
				sb.AppendLine($"Evidence: {finding.Evidence}");
			}

			if (!string.IsNullOrWhiteSpace(finding.FilePath))
			{
				sb.AppendLine();

				if (finding.StartLine > 0)
				{
					sb.AppendLine($"Location: {PathRedactionService.RedactPath(finding.FilePath)}, line {finding.StartLine}");
				}
				else
				{
					sb.AppendLine($"Location: {PathRedactionService.RedactPath(finding.FilePath)}");
				}
			}

			if (!string.IsNullOrWhiteSpace(finding.NuGetAssetPath) && !string.Equals(finding.NuGetAssetPath, finding.FilePath, System.StringComparison.OrdinalIgnoreCase))
			{
				sb.AppendLine();
				sb.AppendLine($"Package asset: {PathRedactionService.RedactPath(finding.NuGetAssetPath)}");
			}

			if (!string.IsNullOrWhiteSpace(finding.PackageId))
			{
				sb.AppendLine();
				sb.AppendLine($"Package: {finding.PackageId} {finding.PackageVersion}");

				if (!string.IsNullOrWhiteSpace(finding.PackageSource))
				{
					var inferred = finding.IsPackageSourceInferred ? " (inferred)" : string.Empty;
					sb.AppendLine($"Package source: {PathRedactionService.RedactMessage(finding.PackageSource)}{inferred}");
				}
			}

			sb.AppendLine();
			sb.AppendLine("Policy evaluation:");
			sb.AppendLine($"  Scanner default action : {finding.ScannerPolicyAction}");
			sb.AppendLine($"  Policy-evaluated action: {finding.PolicyEvaluatedAction}");
			sb.AppendLine($"  Effective action       : {finding.PolicyAction}");

			if (!string.IsNullOrWhiteSpace(finding.PolicyActionReason))
			{
				sb.AppendLine($"  Reason: {finding.PolicyActionReason}");
			}

			sb.AppendLine();

			if (finding.IsNewComparedWithBaseline)
			{
				sb.AppendLine("Baseline: This finding is NEW — it does not appear in the current baseline.");
			}
			else
			{
				sb.AppendLine("Baseline: Finding is present in the baseline.");
			}

			if (finding.FileHasMarkOfTheWeb)
			{
				sb.AppendLine("Note: The source file carries Mark-of-the-Web metadata (downloaded from the internet).");
			}

			if (finding.IsInFileImportedByMultipleProjects)
			{
				sb.AppendLine("Note: The source file is imported by multiple projects.");
			}

			return sb.ToString().TrimEnd();
		}
	}
}
