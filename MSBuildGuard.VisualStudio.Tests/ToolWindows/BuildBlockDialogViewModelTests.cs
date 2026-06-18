using System;
using System.Collections.Generic;
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
			var model         = new BuildBlockDialogViewModel(report, this.tempDir, null, userTrustPath);

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

			var model2 = new BuildBlockDialogViewModel(report, this.tempDir, null, userTrustPath);

			model2.RiskScore.ShouldBe(0);
			model2.RecommendedAction.ShouldBe(RecommendedAction.Allow.ToString());
		}
	}
}
