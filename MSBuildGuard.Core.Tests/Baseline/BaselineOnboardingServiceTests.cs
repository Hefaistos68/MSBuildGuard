using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MSBuildGuard.Core.Baseline;
using MSBuildGuard.Core.Trust;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Baseline
{
	/// <summary>
	/// Tests for <see cref="BaselineOnboardingService"/>.
	/// </summary>
	[TestFixture]
	[Explicit("Requires internet access and local NuGet package cache.")]
	public sealed class BaselineOnboardingServiceTests
	{
		/// <summary>
		/// Verifies that suggestions are generated from a ScanReport containing known NuGet packages.
		/// </summary>
		[Test]
		public async Task GenerateSuggestionsAsync_ShouldGenerateSuggestions_ForNewtonsoftJson()
		{
			var service = new BaselineOnboardingService();
			var report = new ScanReport();

			report.Findings.Add(new Finding
			{
				Id = "MBG001",
				Fingerprint = "fp-1",
				PackageId = "Newtonsoft.Json",
				PackageVersion = "13.0.3",
				FilePath = "somepath"
			});

			var result = await service.GenerateSuggestionsAsync(report, CancellationToken.None);

			result.ShouldNotBeNull();

			// Should contain a package trust recommendation (or signer if local cache exists and it was signed)
			result.Count.ShouldBeGreaterThan(0);

			if (result.Count > 0)
			{
				var suggestion = result.First();

				suggestion.DisplayName.ShouldContain("Newtonsoft.Json");
				suggestion.IsSelected.ShouldBeTrue();
			}
		}

		/// <summary>
		/// Verifies that an unverified/unsigned package like Shouldly generates an unselected package trust suggestion.
		/// </summary>
		[Test]
		public async Task GenerateSuggestionsAsync_ShouldGenerateUnselectedSuggestion_ForShouldly()
		{
			var service = new BaselineOnboardingService();
			var report  = new ScanReport();

			report.Findings.Add(new Finding
			{
				Id             = "MBG002",
				Fingerprint    = "fp-shouldly",
				PackageId      = "Shouldly",
				PackageVersion = "4.3.0",
				FilePath       = "somepath"
			});

			var result = await service.GenerateSuggestionsAsync(report, CancellationToken.None);

			result.ShouldNotBeNull();

			var suggestion = result.FirstOrDefault(item => item.DisplayName.Contains("Shouldly"));

			suggestion.ShouldNotBeNull();
			suggestion.IsSelected.ShouldBeFalse();
			suggestion.ReputationSourceDescription.ShouldBe("Unverified Publisher");
		}

		/// <summary>
		/// Verifies that IsAlreadyTrusted is set to true when the package is already trusted in the trust store.
		/// </summary>
		[Test]
		public async Task GenerateSuggestionsAsync_ShouldSetIsAlreadyTrusted_ForAlreadyTrustedPackage()
		{
			var service = new BaselineOnboardingService();
			var report = new ScanReport();

			report.Findings.Add(new Finding
			{
				Id = "MBG001",
				Fingerprint = "fp-1",
				PackageId = "Newtonsoft.Json",
				PackageVersion = "13.0.3",
				FilePath = "somepath"
			});

			var trustStoreService = new TrustStoreService();
			var userTrustPath = trustStoreService.GetDefaultUserTrustPath();
			var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
			var packageDir = Path.Combine(userHome, ".nuget", "packages", "newtonsoft.json", "13.0.3");

			if (!Directory.Exists(packageDir))
			{
				Assert.Ignore("Local NuGet package directory for Newtonsoft.Json 13.0.3 was not found.");
			}

			var packageHash = TrustStoreService.CalculatePackageDirectoryHash(packageDir);

			trustStoreService.AddPackageTrust(userTrustPath, "Newtonsoft.Json", "13.0.3", packageHash, "Onboarding Test", "TestUser");

			try
			{
				var result = await service.GenerateSuggestionsAsync(report, CancellationToken.None);

				result.ShouldNotBeNull();

				var suggestion = result.FirstOrDefault(item => item.DisplayName.Contains("Newtonsoft.Json"));

				if (suggestion != null)
				{
					suggestion.IsAlreadyTrusted.ShouldBeTrue();
					suggestion.RecommendationReason.ShouldBe("Already trusted in your configuration.");
				}
			}
			finally
			{
				trustStoreService.RemoveDecisionsBySubject(userTrustPath, packageHash, "Clean up", "TestUser");
			}
		}
	}
}
