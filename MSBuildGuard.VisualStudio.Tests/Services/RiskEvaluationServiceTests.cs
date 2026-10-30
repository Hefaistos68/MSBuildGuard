using System;
using System.IO;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.Services;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.Services.Tests
{
	/// <summary>
	/// Unit tests for the <see cref="RiskEvaluationService"/> class.
	/// </summary>
	[TestFixture]
	public sealed class RiskEvaluationServiceTests
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
		/// Verifies that <see cref="RiskEvaluationService.RequiresBuildBlock(BuildBlockDialogViewModel)"/> returns <c>false</c> when the view model is null.
		/// </summary>
		[Test]
		public void RequiresBuildBlock_WhenViewModelIsNull_ReturnsFalse()
		{
			var result = RiskEvaluationService.RequiresBuildBlock((BuildBlockDialogViewModel)null!);

			result.ShouldBeFalse();
		}

		/// <summary>
		/// Verifies that <see cref="RiskEvaluationService.RequiresBuildBlock(BuildBlockDialogViewModel)"/> evaluates both risk score and policy-escalated recommended action when risk score is below 50.
		/// </summary>
		/// <param name="policyAction">The finding policy action to evaluate.</param>
		/// <param name="expectedBlock">Whether the build should be blocked.</param>
		[TestCase(PolicyAction.Allow, false)]
		[TestCase(PolicyAction.Warn, false)]
		[TestCase(PolicyAction.RequireApproval, true)]
		[TestCase(PolicyAction.Block, true)]
		public void RequiresBuildBlock_WhenRiskScoreBelowFifty_EvaluatesRecommendedAction(PolicyAction policyAction, bool expectedBlock)
		{
			var report = new ScanReport();

			report.Target.TargetPath = Path.Combine(this.tempDir, "TestSolution.sln");
			report.Target.TargetKind = TargetKind.Solution;

			var finding = new Finding
			{
				Id                    = "MBG001",
				Title                 = "Policy Finding",
				Severity              = FindingSeverity.Low,
				PolicyEvaluatedAction = policyAction,
				FilePath              = Path.Combine(this.tempDir, "TestProj.csproj"),
				Fingerprint           = "fingerprint-risk-eval"
			};

			report.Findings.Add(finding);

			var userTrustPath = Path.Combine(this.tempDir, "user-trust-eval.json");
			var viewModel     = new BuildBlockDialogViewModel(report, report.Target.TargetPath, null, userTrustPath);
			var shouldBlock   = RiskEvaluationService.RequiresBuildBlock(viewModel);

			viewModel.RiskScore.ShouldBe(5);
			shouldBlock.ShouldBe(expectedBlock);
		}
	}
}
