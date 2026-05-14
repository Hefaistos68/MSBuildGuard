using System;
using System.IO;
using System.Linq;
using MSBuildGuard.Core.Baseline;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Baseline
{
	/// <summary>
	/// Tests for <see cref="BaselineService"/>.
	/// </summary>
	[TestFixture]
	public sealed class BaselineServiceTests
	{
		/// <summary>
		/// Verifies baseline create/save/load roundtrip from report data.
		/// </summary>
		[Test]
		public void BaselineService_ShouldRoundtrip_FromReport()
		{
			var service = new BaselineService();
			var report = new ScanReport();
			var tempFile = Path.Combine(Path.GetTempPath(), $"baseline-{Guid.NewGuid():N}.json");

			report.ScannerVersion = "1.2.3";
			report.FilesScanned.Add(new MsBuildFileRecord { Path = "a.csproj", NormalizedSha256 = "abc" });
			report.Findings.Add(new Finding { Id = "MBG001", Fingerprint = "fp-1", Severity = FindingSeverity.Medium });

			var baseline = service.CreateFromReport(report, "policy-v1", "tester");

			service.Save(tempFile, baseline);

			var loaded = service.Load(tempFile);

			loaded.ScannerVersion.ShouldBe("1.2.3");
			loaded.Files.Count.ShouldBe(1);
			loaded.ApprovedFindings.Single().Fingerprint.ShouldBe("fp-1");
		}
	}
}
