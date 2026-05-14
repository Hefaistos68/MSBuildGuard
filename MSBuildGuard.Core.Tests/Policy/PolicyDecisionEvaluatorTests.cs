using System;
using MSBuildGuard.Core.Baseline;
using MSBuildGuard.Core.Policy;
using MSBuildGuard.Core.Trust;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Policy
{
	/// <summary>
	/// Tests for <see cref="PolicyDecisionEvaluator"/>.
	/// </summary>
	[TestFixture]
	public sealed class PolicyDecisionEvaluatorTests
	{
		/// <summary>
		/// Verifies documented score modifiers are applied to the aggregate risk score.
		/// </summary>
		[Test]
		public void Apply_ShouldUseDocumentedRiskScoreModifiers()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var baseline = new BaselineDocument();
			var trustStore = new TrustStoreDocument();
			var report = new ScanReport
			{
				PolicyProfile = "default",
				Target = new ScanTarget
				{
					TrustContext = new ScanTrustContext
					{
						CommitSha        = "abc123",
						RepositoryRemote = "origin"
					}
				}
			};

			report.FilesScanned.Add(new MsBuildFileRecord
			{
				NormalizedSha256 = "file-hash-100",
				Path             = string.Empty
			});
			var finding = new Finding
			{
				FilePath                          = string.Empty,
				FileHasMarkOfTheWeb               = true,
				Fingerprint                      = "fp-100",
				Id                               = "MBG005",
				IsInFileImportedByMultipleProjects = true,
				IsNewComparedWithBaseline        = true,
				PolicyAction                     = PolicyAction.Block,
				Severity                         = FindingSeverity.High
			};

			report.Findings.Add(finding);
			trustStore.Decisions.Add(new TrustDecisionEntry
			{
				CommitSha        = "abc123",
				CreatedAtUtc     = DateTimeOffset.UtcNow,
				Decision         = "TrustUntilChanged",
				DecisionId       = Guid.NewGuid().ToString("N"),
				PolicyProfile    = "default",
				RepositoryRemote = "origin",
				Scope            = "Repository"
			});
			trustStore.Decisions.Add(new TrustDecisionEntry
			{
				CreatedAtUtc = DateTimeOffset.UtcNow,
				Decision     = "TrustUntilChanged",
				DecisionId   = Guid.NewGuid().ToString("N"),
				Scope        = "Finding",
				SubjectHash  = "fp-100"
			});

			evaluator.Apply(report, policy, baseline, trustStore);

			report.RiskScore.ShouldBe(75);
			report.RecommendedAction.ShouldBe(RecommendedAction.Block);
			finding.PolicyAction.ShouldBe(PolicyAction.Block);
		}

		/// <summary>
		/// Verifies strict incomplete-analysis policy escalates the report recommendation.
		/// </summary>
		[Test]
		public void Apply_ShouldBlockReport_WhenStrictIncompleteAnalysisPolicyIsEnabled()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var report = new ScanReport();

			policy.StrictMode = true;
			policy.IncompleteAnalysisAction = PolicyAction.RequireApproval;

			report.Findings.Add(new Finding
			{
				Id = "MBG012",
				PolicyAction = PolicyAction.Warn,
				Severity = FindingSeverity.Medium
			});

			evaluator.Apply(report, policy, null, null);

			report.RiskScore.ShouldBe(20);
			report.RecommendedAction.ShouldBe(RecommendedAction.Block);
			report.Findings[0].PolicyAction.ShouldBe(PolicyAction.Block);
			report.Findings[0].ScannerPolicyAction.ShouldBe(PolicyAction.Warn);
			report.Findings[0].PolicyEvaluatedAction.ShouldBe(PolicyAction.Block);
			report.Findings[0].PolicyActionReason.ShouldContain("Strict mode escalated");
		}

		/// <summary>
		/// Verifies file-scope trust reduces risk for findings in the matching trusted file context.
		/// </summary>
		[Test]
		public void Apply_ShouldUseFileScopeTrustApproval_WhenFileHashAndContextMatch()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var trustStore = new TrustStoreDocument();
			var report = new ScanReport
			{
				PolicyProfile = "default",
				Target = new ScanTarget
				{
					TrustContext = new ScanTrustContext
					{
						Branch           = "main",
						CommitSha        = "abc123",
						RepositoryRemote = "origin"
					}
				}
			};

			report.FilesScanned.Add(new MsBuildFileRecord
			{
				NormalizedSha256 = "file-hash-1",
				Path             = "a.csproj"
			});

			report.Findings.Add(new Finding
			{
				FilePath     = "a.csproj",
				Fingerprint  = "fp-300",
				Id           = "MBG001",
				PolicyAction = PolicyAction.RequireApproval,
				Severity     = FindingSeverity.Medium
			});

			trustStore.Decisions.Add(new TrustDecisionEntry
			{
				Branch           = "main",
				CommitSha        = "abc123",
				CreatedAtUtc     = DateTimeOffset.UtcNow,
				Decision         = "TrustUntilChanged",
				DecisionId       = Guid.NewGuid().ToString("N"),
				PolicyProfile    = "default",
				RepositoryRemote = "origin",
				Scope            = "File",
				SubjectHash      = "file-hash-1"
			});

			evaluator.Apply(report, policy, null, trustStore);

			report.RiskScore.ShouldBe(0);
			report.RecommendedAction.ShouldBe(RecommendedAction.RequireApproval);
		}

		/// <summary>
		/// Verifies report recommendation follows the score band when no stricter policy action is present.
		/// </summary>
		[Test]
		public void Apply_ShouldUseScoreBandRecommendation_WhenPolicyActionIsNotStricter()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var report = new ScanReport();

			report.Findings.Add(new Finding
			{
				FileHasMarkOfTheWeb = true,
				Id                 = "MBG011",
				PolicyAction       = PolicyAction.Allow,
				Severity           = FindingSeverity.Info
			});

			evaluator.Apply(report, policy, null, null);

			report.RiskScore.ShouldBe(30);
			report.RecommendedAction.ShouldBe(RecommendedAction.Warn);
		}

		/// <summary>
		/// Verifies package-origin findings contribute deterministic provenance-based score modifiers.
		/// </summary>
		[Test]
		public void Apply_ShouldIncreaseRiskScore_ForTransitiveBuildTransitivePackageAssets()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var report = new ScanReport();

			report.Findings.Add(new Finding
			{
				Id                 = "MBG004",
				IsTransitivePackage = true,
				PackageAssetKind   = PackageAssetKind.BuildTransitive,
				PolicyAction       = PolicyAction.Warn,
				Severity           = FindingSeverity.Info
			});

			evaluator.Apply(report, policy, null, null);

			report.RiskScore.ShouldBe(25);
			report.RecommendedAction.ShouldBe(RecommendedAction.Warn);
		}

		/// <summary>
		/// Verifies blocked package sources escalate the finding and report recommendation.
		/// </summary>
		[Test]
		public void Apply_ShouldBlockFinding_WhenPackageSourceIsBlockedByPolicyAndSourceIsEvidenceBacked()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var report = new ScanReport();

			policy.BlockedPackageSources.Add("https://blocked.example/v3/index.json");

			report.Findings.Add(new Finding
			{
				Id                     = "MBG004",
				IsPackageSourceInferred = false,
				PackageId              = "Contoso.Build",
				PackageSource          = "https://blocked.example/v3/index.json/",
				PolicyAction           = PolicyAction.Warn,
				Severity               = FindingSeverity.Info
			});

			evaluator.Apply(report, policy, null, null);

			report.Findings[0].PolicyAction.ShouldBe(PolicyAction.Block);
			report.RecommendedAction.ShouldBe(RecommendedAction.Block);
		}

		/// <summary>
		/// Verifies unapproved package sources use the configured fallback action when allowed sources are enforced.
		/// </summary>
		[Test]
		public void Apply_ShouldUseUnapprovedPackageSourceAction_WhenPackageSourceIsNotAllowed()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var report = new ScanReport();

			policy.AllowedPackageSources.Add("https://trusted.example/v3/index.json");
			policy.UnapprovedPackageSourceAction = PolicyAction.RequireApproval;

			report.Findings.Add(new Finding
			{
				Id                     = "MBG004",
				IsPackageSourceInferred = false,
				PackageId              = "Contoso.Build",
				PackageSource          = "https://unapproved.example/v3/index.json",
				PolicyAction           = PolicyAction.Warn,
				Severity               = FindingSeverity.Info
			});

			evaluator.Apply(report, policy, null, null);

			report.Findings[0].PolicyAction.ShouldBe(PolicyAction.RequireApproval);
			report.RecommendedAction.ShouldBe(RecommendedAction.RequireApproval);
		}

		/// <summary>
		/// Verifies inferred package source provenance uses the configured unapproved action.
		/// </summary>
		[Test]
		public void Apply_ShouldUseUnapprovedPackageSourceAction_WhenPackageSourceIsInferred()
		{
			var evaluator = new PolicyDecisionEvaluator();
			var policy = new PolicyService().CreateDefault();
			var report = new ScanReport();

			policy.BlockedPackageSources.Add("https://blocked.example/v3/index.json");
			policy.UnapprovedPackageSourceAction = PolicyAction.RequireApproval;

			report.Findings.Add(new Finding
			{
				Id                     = "MBG004",
				IsPackageSourceInferred = true,
				PackageId              = "Contoso.Build",
				PackageSource          = "https://blocked.example/v3/index.json",
				PolicyAction           = PolicyAction.Warn,
				Severity               = FindingSeverity.Info
			});

			evaluator.Apply(report, policy, null, null);

			report.Findings[0].PolicyAction.ShouldBe(PolicyAction.RequireApproval);
			report.RecommendedAction.ShouldBe(RecommendedAction.RequireApproval);
		}
	}
}
