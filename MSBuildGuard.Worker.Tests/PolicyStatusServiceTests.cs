using System;
using System.IO;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Policy;
using MSBuildGuard.Worker;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Worker.Tests
{
	/// <summary>
	/// Unit tests verifying the configuration resolution logic in <see cref="PolicyStatusService"/>.
	/// </summary>
	[TestFixture]
	public sealed class PolicyStatusServiceTests
	{
		/// <summary>
		/// Verifies that loading a corrupted policy file returns a fail-safe policy where all actions default to block.
		/// </summary>
		[Test]
		public void GetEffectivePolicy_ShouldReturnFailSafeBlockPolicy_WhenPolicyFileIsCorrupt()
		{
			var service = new PolicyStatusService();
			var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

			Directory.CreateDirectory(tempDir);
			var policyPath = Path.Combine(tempDir, ".msbuildguard", "policy.json");

			Directory.CreateDirectory(Path.GetDirectoryName(policyPath)!);
			File.WriteAllText(policyPath, "{ invalid json content }");

			try
			{
				var effectivePolicy = service.GetEffectivePolicy(tempDir, null);

				effectivePolicy.ShouldNotBeNull();
				effectivePolicy.Mode.ShouldBe("block");
				effectivePolicy.IncompleteAnalysisAction.ShouldBe(PolicyAction.Block);
				effectivePolicy.UnapprovedPackageSourceAction.ShouldBe(PolicyAction.Block);
				effectivePolicy.MinimumActionBySeverity[FindingSeverity.Critical].ShouldBe(PolicyAction.Block);
				effectivePolicy.MinimumActionBySeverity[FindingSeverity.High].ShouldBe(PolicyAction.Block);
				effectivePolicy.MinimumActionBySeverity[FindingSeverity.Medium].ShouldBe(PolicyAction.Block);
				effectivePolicy.MinimumActionBySeverity[FindingSeverity.Low].ShouldBe(PolicyAction.Block);
				effectivePolicy.MinimumActionBySeverity[FindingSeverity.Info].ShouldBe(PolicyAction.Block);
			}
			finally
			{
				try
				{
					Directory.Delete(tempDir, true);
				}
				catch
				{
				}
			}
		}
	}
}
