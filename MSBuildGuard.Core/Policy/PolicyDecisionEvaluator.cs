using System;
using System.Linq;
using MSBuildGuard.Core.Baseline;
using MSBuildGuard.Core.Trust;

namespace MSBuildGuard.Core.Policy
{
	/// <summary>
	/// Evaluates policy and trust decisions for scan findings.
	/// </summary>
	public sealed class PolicyDecisionEvaluator
	{
		/// <summary>
		/// Applies policy actions and score modifiers for baseline/trust context.
		/// </summary>
		/// <param name="report">The scan report to evaluate.</param>
		/// <param name="policy">The effective policy.</param>
		/// <param name="baseline">Optional baseline document.</param>
		/// <param name="trustStore">Optional trust store document.</param>
		public void Apply(ScanReport report, PolicyDocument policy, BaselineDocument? baseline, TrustStoreDocument? trustStore)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (policy == null)
			{
				throw new ArgumentNullException(nameof(policy));
			}

			var baselineFingerprints = baseline == null
				? Array.Empty<string>()
				: baseline.ApprovedFindings.Select(item => item.Fingerprint).ToArray();
			var policyService = new PolicyService();
			var trustService = new TrustStoreService();
			var repositoryTrusted = trustStore != null &&
				!string.IsNullOrWhiteSpace(report.Target.TrustContext.RepositoryRemote) &&
				!string.IsNullOrWhiteSpace(report.Target.TrustContext.CommitSha) &&
				trustService.IsRepositoryTrusted(trustStore, report.Target.TrustContext.RepositoryRemote, report.Target.TrustContext.Branch, report.Target.TrustContext.CommitSha, report.PolicyProfile);
			var score = 0;

			foreach (var finding in report.Findings)
			{
				finding.ScannerPolicyAction = finding.PolicyAction;

				var resolvedAction = policyService.ResolveAction(policy, finding);
				resolvedAction = MaxPolicyAction(resolvedAction, ResolvePackageSourcePolicyAction(policy, finding));

				finding.PolicyEvaluatedAction = resolvedAction;
				finding.PolicyActionReason = ResolvePolicyActionReason(policy, finding, resolvedAction);
				finding.PolicyAction = resolvedAction;
				score += SeverityScore(finding.Severity);

				if (finding.FileHasMarkOfTheWeb)
				{
					score += 30;
				}

				if (finding.IsInFileImportedByMultipleProjects)
				{
					score += 20;
				}

				if (finding.IsNewComparedWithBaseline)
				{
					score += 25;
				}

				score += PackageProvenanceScore(finding);

				var fileRecord = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));

				if (trustStore != null &&
					!string.IsNullOrWhiteSpace(finding.Fingerprint) &&
					fileRecord != null &&
					trustService.IsFindingApproved(trustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile))
				{
					score -= 30;
				}

				if (repositoryTrusted)
				{
					score -= 20;
				}
			}

			report.RiskScore = Math.Max(0, score);
			var highestPolicyAction = report.Findings.Count == 0
				? PolicyAction.Allow
				: report.Findings.Max(item => item.PolicyAction);
			var scoreRecommendedAction = MapRecommendedAction(report.RiskScore);
			report.RecommendedAction = MaxRecommendedAction(scoreRecommendedAction, MapRecommendedAction(highestPolicyAction));
		}

		/// <summary>
		/// Maps a numeric risk score to a recommended action.
		/// </summary>
		/// <param name="riskScore">The risk score to map.</param>
		/// <returns>The recommended action corresponding to the risk score.</returns>
		private static RecommendedAction MapRecommendedAction(int riskScore)
		{
			if (riskScore >= 100)
			{
				return RecommendedAction.Block;
			}

			if (riskScore >= 50)
			{
				return RecommendedAction.RequireApproval;
			}

			if (riskScore >= 20)
			{
				return RecommendedAction.Warn;
			}

			return RecommendedAction.Allow;
		}

		/// <summary>
		/// Maps a policy action to its corresponding recommended action.
		/// </summary>
		/// <param name="policyAction">The policy action to map.</param>
		/// <returns>The mapped recommended action.</returns>
		private static RecommendedAction MapRecommendedAction(PolicyAction policyAction)
		{
			switch (policyAction)
			{
				case PolicyAction.Block:
					return RecommendedAction.Block;
				case PolicyAction.RequireApproval:
					return RecommendedAction.RequireApproval;
				case PolicyAction.Warn:
					return RecommendedAction.Warn;
				default:
					return RecommendedAction.Allow;
			}
		}

		/// <summary>
		/// Selects the most restrictive recommended action between two options.
		/// </summary>
		/// <param name="left">The first recommended action.</param>
		/// <param name="right">The second recommended action.</param>
		/// <returns>The more restrictive recommended action.</returns>
		private static RecommendedAction MaxRecommendedAction(RecommendedAction left, RecommendedAction right)
		{
			return (RecommendedAction)Math.Max((int)left, (int)right);
		}

		/// <summary>
		/// Computes a risk score modifier based on the severity of a finding.
		/// </summary>
		/// <param name="severity">The severity of the finding.</param>
		/// <returns>The risk score value associated with the severity.</returns>
		private static int SeverityScore(FindingSeverity severity)
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

		/// <summary>
		/// Computes additional risk score modifiers based on package provenance and asset kinds.
		/// </summary>
		/// <param name="finding">The finding to evaluate.</param>
		/// <returns>The calculated provenance score modifier.</returns>
		private static int PackageProvenanceScore(Finding finding)
		{
			var score = 0;

			if (finding.IsTransitivePackage)
			{
				score += 10;
			}

			switch (finding.PackageAssetKind)
			{
				case PackageAssetKind.BuildTransitive:
					score += 15;
					break;
				case PackageAssetKind.BuildMultiTargeting:
					score += 10;
					break;
				case PackageAssetKind.Build:
				case PackageAssetKind.Sdk:
					score += 5;
					break;
			}

			return score;
		}

		/// <summary>
		/// Resolves the policy action for a finding based on its package source constraints.
		/// </summary>
		/// <param name="policy">The policy document containing package source rules.</param>
		/// <param name="finding">The finding to evaluate.</param>
		/// <returns>The policy action based on package source rules.</returns>
		private static PolicyAction ResolvePackageSourcePolicyAction(PolicyDocument policy, Finding finding)
		{
			if (string.IsNullOrWhiteSpace(finding.PackageId))
			{
				return PolicyAction.Allow;
			}

			var hasSourcePolicyConstraints = policy.BlockedPackageSources.Count > 0 || policy.AllowedPackageSources.Count > 0;

			if (!hasSourcePolicyConstraints)
			{
				return PolicyAction.Allow;
			}

			if (finding.IsPackageSourceInferred || string.IsNullOrWhiteSpace(finding.PackageSource))
			{
				return policy.UnapprovedPackageSourceAction;
			}

			if (IsPackageSourceMatch(policy.BlockedPackageSources, finding.PackageSource))
			{
				return PolicyAction.Block;
			}

			if (policy.AllowedPackageSources.Count == 0)
			{
				return PolicyAction.Allow;
			}

			if (IsPackageSourceMatch(policy.AllowedPackageSources, finding.PackageSource))
			{
				return PolicyAction.Allow;
			}

			return policy.UnapprovedPackageSourceAction;
		}

		/// <summary>
		/// Determines whether a given package source matches any of the configured sources.
		/// </summary>
		/// <param name="configuredSources">The list of configured package sources.</param>
		/// <param name="packageSource">The package source to check.</param>
		/// <returns><c>true</c> if a match is found; otherwise, <c>false</c>.</returns>
		private static bool IsPackageSourceMatch(System.Collections.Generic.IEnumerable<string> configuredSources, string packageSource)
		{
			var normalizedPackageSource = NormalizePackageSource(packageSource);

			if (string.IsNullOrWhiteSpace(normalizedPackageSource))
			{
				return false;
			}

			foreach (var configuredSource in configuredSources)
			{
				if (string.Equals(NormalizePackageSource(configuredSource), normalizedPackageSource, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Normalizes a package source string by trimming whitespace and trailing slashes.
		/// </summary>
		/// <param name="packageSource">The package source string to normalize.</param>
		/// <returns>The normalized package source string.</returns>
		private static string NormalizePackageSource(string packageSource)
		{
			if (string.IsNullOrWhiteSpace(packageSource))
			{
				return string.Empty;
			}

			return packageSource.Trim().TrimEnd('/', '\\');
		}

		/// <summary>
		/// Selects the most restrictive policy action between two options.
		/// </summary>
		/// <param name="left">The first policy action.</param>
		/// <param name="right">The second policy action.</param>
		/// <returns>The more restrictive policy action.</returns>
		private static PolicyAction MaxPolicyAction(PolicyAction left, PolicyAction right)
		{
			return (PolicyAction)Math.Max((int)left, (int)right);
		}

		/// <summary>
		/// Resolves the reason description for the applied policy action.
		/// </summary>
		/// <param name="policy">The policy document containing strict mode settings.</param>
		/// <param name="finding">The finding being evaluated.</param>
		/// <param name="resolvedAction">The final resolved policy action.</param>
		/// <returns>A string describing the reason for the policy action decision.</returns>
		private static string ResolvePolicyActionReason(PolicyDocument policy, Finding finding, PolicyAction resolvedAction)
		{
			if (finding.ScannerPolicyAction == resolvedAction)
			{
				return string.Empty;
			}

			if (string.Equals(finding.Id, "MBG012", StringComparison.OrdinalIgnoreCase) && policy.StrictMode)
			{
				return "Strict mode escalated incomplete-analysis finding action.";
			}

			return "Policy evaluation changed the scanner default action.";
		}
	}
}
