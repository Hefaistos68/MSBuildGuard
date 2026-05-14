using System.Linq;
using MSBuildGuard.Core.Baseline;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Baseline
{
	/// <summary>
	/// Tests for <see cref="BaselineComparer"/>.
	/// </summary>
	[TestFixture]
	public sealed class BaselineComparerTests
	{
		/// <summary>
		/// Verifies drift detection when files or findings differ from baseline.
		/// </summary>
		[Test]
		public void BaselineComparer_ShouldDetectDrift_WhenReportDiffers()
		{
			var comparer = new BaselineComparer();
			var report = new ScanReport();
			var baseline = new BaselineDocument();

			report.FilesScanned.Add(new MsBuildFileRecord { Path = "b.targets", NormalizedSha256 = "new" });
			report.Findings.Add(new Finding { Id = "MBG005", Fingerprint = "new-fp" });
			baseline.Files.Add(new BaselineFileEntry { Path = "a.targets", NormalizedSha256 = "old" });
			baseline.ApprovedFindings.Add(new BaselineFindingEntry { Fingerprint = "old-fp", RuleId = "MBG001" });

			var result = comparer.Compare(report, baseline);

			result.DriftDetected.ShouldBeTrue();
			result.NewFiles.Count.ShouldBe(1);
			result.RemovedFiles.Count.ShouldBe(1);
			result.NewFindings.Count.ShouldBe(2);
			report.BaselineComparison.DriftDetected.ShouldBeTrue();
		}

		/// <summary>
		/// Verifies MBG010 finding when baseline comparison discovers a new .targets file.
		/// </summary>
		[Test]
		public void BaselineComparer_ShouldAddMbg010_WhenNewTargetsFileAppears()
		{
			var comparer = new BaselineComparer();
			var report = new ScanReport();
			var baseline = new BaselineDocument();

			report.FilesScanned.Add(new MsBuildFileRecord { Path = "new.targets", NormalizedSha256 = "abc" });

			var result = comparer.Compare(report, baseline);
			var mbg010 = result.NewFindings.SingleOrDefault(finding => finding.Id == "MBG010");

			mbg010.ShouldNotBeNull();
			mbg010!.FilePath.ShouldBe("new.targets");
			mbg010.Fingerprint.ShouldBe("MBG010|new.targets");
		}

		/// <summary>
		/// Verifies new findings are marked as new compared with baseline.
		/// </summary>
		[Test]
		public void BaselineComparer_ShouldMarkFindingAsNewComparedWithBaseline_WhenFingerprintIsNotApproved()
		{
			var comparer = new BaselineComparer();
			var report = new ScanReport();
			var baseline = new BaselineDocument();

			report.Findings.Add(new Finding
			{
				Fingerprint = "new-fp",
				Id          = "MBG001"
			});
			baseline.ApprovedFindings.Add(new BaselineFindingEntry
			{
				Fingerprint = "old-fp",
				RuleId      = "MBG001"
			});

			var result = comparer.Compare(report, baseline);

			result.NewFindings.Single().IsNewComparedWithBaseline.ShouldBeTrue();
		}

		/// <summary>
		/// Verifies package-origin drift is labeled separately from repository file drift.
		/// </summary>
		[Test]
		public void BaselineComparer_ShouldLabelPackageAssetDrift_WhenNewFileOriginatesFromNuGetPackage()
		{
			var comparer = new BaselineComparer();
			var report = new ScanReport();
			var baseline = new BaselineDocument();

			report.FilesScanned.Add(new MsBuildFileRecord
			{
				NormalizedSha256 = "abc",
				PackageAssetKind = PackageAssetKind.BuildTransitive,
				PackageId        = "Contoso.Build",
				PackageVersion   = "1.2.3",
				Path             = "C:\\packages\\contoso.build\\1.2.3\\buildTransitive\\Contoso.Build.targets"
			});

			var result = comparer.Compare(report, baseline);

			result.NewFiles.Single().ShouldContain("NuGet package asset: Contoso.Build 1.2.3 (BuildTransitive)");
			result.NewFiles.Single().ShouldContain("Contoso.Build.targets");
		}

		/// <summary>
		/// Verifies MBG003 drift synthesis when InitialTargets finding is new and file content changed.
		/// </summary>
		[Test]
		public void BaselineComparer_ShouldAddMbg003Changed_WhenInitialTargetsFindingIsNewAndFileChanged()
		{
			var comparer = new BaselineComparer();
			var report = new ScanReport();
			var baseline = new BaselineDocument();

			report.FilesScanned.Add(new MsBuildFileRecord
			{
				NormalizedSha256 = "new-hash",
				Path = "App.csproj"
			});
			report.Findings.Add(new Finding
			{
				FilePath = "App.csproj",
				Fingerprint = "fp-current",
				Id = "MBG003"
			});
			baseline.Files.Add(new BaselineFileEntry
			{
				NormalizedSha256 = "old-hash",
				Path = "App.csproj"
			});

			var result = comparer.Compare(report, baseline);
			var changedFinding = result.NewFindings.SingleOrDefault(finding => finding.Id == "MBG003_CHANGED");

			changedFinding.ShouldNotBeNull();
			changedFinding!.FilePath.ShouldBe("App.csproj");
			changedFinding.PolicyAction.ShouldBe(PolicyAction.Block);
		}

		/// <summary>
		/// Verifies MBG003 drift is not synthesized when finding fingerprint is already baseline-approved.
		/// </summary>
		[Test]
		public void BaselineComparer_ShouldNotAddMbg003Changed_WhenInitialTargetsFindingFingerprintIsApproved()
		{
			var comparer = new BaselineComparer();
			var report = new ScanReport();
			var baseline = new BaselineDocument();

			report.FilesScanned.Add(new MsBuildFileRecord
			{
				NormalizedSha256 = "new-hash",
				Path = "App.csproj"
			});
			report.Findings.Add(new Finding
			{
				FilePath = "App.csproj",
				Fingerprint = "fp-approved",
				Id = "MBG003"
			});
			baseline.Files.Add(new BaselineFileEntry
			{
				NormalizedSha256 = "old-hash",
				Path = "App.csproj"
			});
			baseline.ApprovedFindings.Add(new BaselineFindingEntry
			{
				Fingerprint = "fp-approved",
				RuleId = "MBG003"
			});

			var result = comparer.Compare(report, baseline);

			result.NewFindings.Any(finding => finding.Id == "MBG003_CHANGED").ShouldBeFalse();
		}
	}
}
