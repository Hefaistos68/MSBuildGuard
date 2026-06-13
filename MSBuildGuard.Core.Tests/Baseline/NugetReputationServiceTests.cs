using System;
using System.Threading;
using System.Threading.Tasks;
using MSBuildGuard.Core.Baseline;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Baseline
{
	/// <summary>
	/// Tests for <see cref="NugetReputationService"/>.
	/// </summary>
	[TestFixture]
	public sealed class NugetReputationServiceTests
	{
		/// <summary>
		/// Verifies that looking up a verified package returns correct metadata.
		/// </summary>
		[Test]
		public async Task GetReputationAsync_ShouldReturnMetadata_ForKnownPackage()
		{
			var service = new NugetReputationService();

			var result = await service.GetReputationAsync("Newtonsoft.Json", CancellationToken.None);

			result.ShouldNotBeNull();
			result.PackageId.ShouldBe("Newtonsoft.Json");
			result.IsVerified.ShouldBeTrue();
			result.TotalDownloads.ShouldBeGreaterThan(0);
			result.Owners.ShouldContain("newtonsoft");
		}

		/// <summary>
		/// Verifies that lookup fails gracefully with null for invalid package IDs.
		/// </summary>
		[Test]
		public async Task GetReputationAsync_ShouldReturnNull_ForInvalidPackage()
		{
			var service = new NugetReputationService();

			var result = await service.GetReputationAsync(string.Empty, CancellationToken.None);

			result.ShouldBeNull();
		}
	}
}
