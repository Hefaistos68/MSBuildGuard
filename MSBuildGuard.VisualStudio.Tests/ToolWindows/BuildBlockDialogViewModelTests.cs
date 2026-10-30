using System;
using System.IO;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.ToolWindows.Tests
{
	/// <summary>
	/// Unit tests for the <see cref="BuildBlockDialogViewModel"/> class.
	/// </summary>
	[TestFixture]
	public sealed class BuildBlockDialogViewModelTests
	{
		private string tempDir = string.Empty;

		/// <summary>
		/// Sets up the test environment.
		/// </summary>
		[SetUp]
		public void SetUp()
		{
			this.tempDir = Path.Combine(Path.GetTempPath(), "MSBuildGuardTests", Guid.NewGuid().ToString("N"));

			Directory.CreateDirectory(this.tempDir);
		}

		/// <summary>
		/// Tears down the test environment.
		/// </summary>
		[TearDown]
		public void TearDown()
		{
			if (Directory.Exists(this.tempDir))
			{
				try
				{
					Directory.Delete(this.tempDir, true);
				}
				catch
				{
					// Ignore clean up errors.
				}
			}
		}

		/// <summary>
		/// Verifies that risk score calculation correctly ignores trusted findings.
		/// </summary>
		[Test]
		public void Constructor_WithTrustedFindings_CalculatesCorrectRiskScore()
		{
			var report = new ScanReport();

			report.Target.TargetPath = Path.Combine(this.tempDir, "TestSolution.sln");
			report.Target.TargetKind = TargetKind.Solution;

			var finding = new Finding
			{
				Id          = "MBG001",
				Title       = "Test Finding",
				Severity    = FindingSeverity.Medium,
				FilePath    = Path.Combine(this.tempDir, "TestProj.csproj"),
				Fingerprint = "fingerprint-1"
			};

			report.Findings.Add(finding);

			var fileRecord = new MsBuildFileRecord
			{
				Path             = finding.FilePath,
				NormalizedSha256 = "sha256-hash-value"
			};

			report.FilesScanned.Add(fileRecord);

			var userTrustPath = Path.Combine(this.tempDir, "user-trust.json");
			var model         = new BuildBlockDialogViewModel(report, report.Target.TargetPath, null, userTrustPath);

			// Initially, the finding is not trusted.
			model.RiskScore.ShouldBe(20);

			// Now we write a trust entry for it.
			var trustStoreService = new TrustStoreService();

			trustStoreService.AddDecision(userTrustPath, new TrustDecisionEntry
			{
				DecisionId   = Guid.NewGuid().ToString("N"),
				Scope        = "Finding",
				SubjectHash  = "fingerprint-1",
				Decision     = "Trust",
				Reason       = "Test trust",
				UserSid      = "TestSid",
				CreatedAtUtc = DateTimeOffset.UtcNow
			});

			var model2 = new BuildBlockDialogViewModel(report, report.Target.TargetPath, null, userTrustPath);

			model2.RiskScore.ShouldBe(0);
			model2.RiskLevel.ShouldBe("Low");
			model2.RecommendedAction.ShouldBe(RecommendedAction.Allow.ToString());
		}

		/// <summary>
		/// Verifies that <see cref="BuildBlockDialogViewModel.RiskLevel"/> maps risk score thresholds to the expected level strings.
		/// </summary>
		/// <param name="severity">The finding severity to evaluate.</param>
		/// <param name="expectedLevel">The expected risk level label.</param>
		[TestCase(FindingSeverity.Low, "Low")]
		[TestCase(FindingSeverity.Medium, "Medium")]
		[TestCase(FindingSeverity.Critical, "High")]
		public void RiskLevel_WhenEvaluatedFromSeverity_ReturnsExpectedLevel(FindingSeverity severity, string expectedLevel)
		{
			var report = new ScanReport();

			report.Target.TargetPath = Path.Combine(this.tempDir, "TestSolution.sln");
			report.Target.TargetKind = TargetKind.Solution;

			var finding = new Finding
			{
				Id          = "MBG001",
				Title       = "Test Finding",
				Severity    = severity,
				FilePath    = Path.Combine(this.tempDir, "TestProj.csproj"),
				Fingerprint = "fingerprint-level"
			};

			report.Findings.Add(finding);

			var userTrustPath = Path.Combine(this.tempDir, "user-trust-level.json");
			var model         = new BuildBlockDialogViewModel(report, report.Target.TargetPath, null, userTrustPath);

			model.RiskLevel.ShouldBe(expectedLevel);
		}

		/// <summary>
		/// Verifies that <see cref="BuildBlockDialogViewModel.RecommendedAction"/> escalates to match the highest finding policy action even when the numeric risk score is low.
		/// </summary>
		/// <param name="policyAction">The policy action evaluated for the finding.</param>
		/// <param name="expectedAction">The expected recommended action string.</param>
		[TestCase(PolicyAction.Warn, "Warn")]
		[TestCase(PolicyAction.RequireApproval, "RequireApproval")]
		[TestCase(PolicyAction.Block, "Block")]
		public void RecommendedAction_WhenPolicyEvaluatedActionExceedsRiskScore_EscalatesRecommendedAction(PolicyAction policyAction, string expectedAction)
		{
			var report = new ScanReport();

			report.Target.TargetPath = Path.Combine(this.tempDir, "TestSolution.sln");
			report.Target.TargetKind = TargetKind.Solution;

			var finding = new Finding
			{
				Id                    = "MBG001",
				Title                 = "Low Severity Policy Escalated Finding",
				Severity              = FindingSeverity.Low,
				PolicyEvaluatedAction = policyAction,
				FilePath              = Path.Combine(this.tempDir, "TestProj.csproj"),
				Fingerprint           = "fingerprint-policy-escalation"
			};

			report.Findings.Add(finding);

			var userTrustPath = Path.Combine(this.tempDir, "user-trust-policy.json");
			var model         = new BuildBlockDialogViewModel(report, report.Target.TargetPath, null, userTrustPath);

			model.RiskScore.ShouldBe(5);
			model.RiskLevel.ShouldBe("Low");
			model.RecommendedAction.ShouldBe(expectedAction);
			model.Findings.Count.ShouldBe(1);
			model.Findings[0].Action.ShouldBe(policyAction.ToString());
		}

		/// <summary>
		/// Verifies that findings with <see cref="PolicyAction.Allow"/> contribute to the active risk score but are omitted from actionable finding rows.
		/// </summary>
		[Test]
		public void Findings_WhenPolicyEvaluatedActionIsAllow_ExcludesFindingFromActionableRows()
		{
			var report = new ScanReport();

			report.Target.TargetPath = Path.Combine(this.tempDir, "TestSolution.sln");
			report.Target.TargetKind = TargetKind.Solution;

			var allowedFinding = new Finding
			{
				Id                    = "MBG001",
				Title                 = "Allowed Finding",
				Severity              = FindingSeverity.Medium,
				PolicyEvaluatedAction = PolicyAction.Allow,
				FilePath              = Path.Combine(this.tempDir, "TestProj.csproj"),
				Fingerprint           = "fingerprint-allowed"
			};

			var blockedFinding = new Finding
			{
				Id                    = "MBG002",
				Title                 = "Blocked Finding",
				Severity              = FindingSeverity.Low,
				PolicyEvaluatedAction = PolicyAction.Block,
				FilePath              = Path.Combine(this.tempDir, "TestProj.csproj"),
				Fingerprint           = "fingerprint-blocked"
			};

			report.Findings.Add(allowedFinding);
			report.Findings.Add(blockedFinding);

			var userTrustPath = Path.Combine(this.tempDir, "user-trust-filter.json");
			var model         = new BuildBlockDialogViewModel(report, report.Target.TargetPath, null, userTrustPath);

			model.RiskScore.ShouldBe(25);
			model.Findings.Count.ShouldBe(1);
			model.Findings[0].RuleId.ShouldBe("MBG002");
		}
	}
}
