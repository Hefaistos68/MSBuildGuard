using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MSBuildGuard.Core.Trust;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Represents the target scope of a suggested trust.
	/// </summary>
	public enum TrustSuggestionScope
	{
		/// <summary>
		/// Trust all assemblies bearing the same certificate signer.
		/// </summary>
		Signer,

		/// <summary>
		/// Trust the NuGet package ID and version via directory hash.
		/// </summary>
		Package,

		/// <summary>
		/// Trust the specific assembly name and version.
		/// </summary>
		Assembly
	}

	/// <summary>
	/// Represents an onboarding trust suggestion based on reputation or signature analysis.
	/// </summary>
	public sealed class TrustSuggestion
	{
		/// <summary>
		/// Gets or sets a value indicating whether this suggestion is selected by default.
		/// </summary>
		public bool IsSelected { get; set; }

		/// <summary>
		/// Gets or sets the target scope for trust.
		/// </summary>
		public TrustSuggestionScope Scope { get; set; }

		/// <summary>
		/// Gets or sets the main subject identifier.
		/// </summary>
		public string Subject { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the display name or friendly description.
		/// </summary>
		public string DisplayName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the reason why this trust suggestion is recommended.
		/// </summary>
		public string RecommendationReason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the reputation details or description.
		/// </summary>
		public string ReputationSourceDescription { get; set; } = string.Empty;

		/// <summary>
		/// Gets additional metadata for creating the trust decision.
		/// </summary>
		public Dictionary<string, string> Metadata { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Analyzes scan reports to intelligently suggest baseline trusts.
	/// </summary>
	public sealed class BaselineOnboardingService
	{
		private readonly NugetReputationService reputationService;

		/// <summary>
		/// Initializes a new instance of the <see cref="BaselineOnboardingService"/> class.
		/// </summary>
		public BaselineOnboardingService()
		{
			this.reputationService = new NugetReputationService();
		}

		/// <summary>
		/// Analyzes a scan report and generates recommended trust decisions.
		/// </summary>
		/// <param name="report">The scan report to analyze.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A list of recommended trust suggestions.</returns>
		public async Task<List<TrustSuggestion>> GenerateSuggestionsAsync(ScanReport report, CancellationToken cancellationToken)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			var suggestions = new List<TrustSuggestion>();
			var processedPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var processedSigners = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var signatureService = new AssemblySignatureService();

			foreach (var finding in report.Findings)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var packageId = finding.PackageId;
				var packageVersion = finding.PackageVersion;

				if (string.IsNullOrWhiteSpace(packageId) || string.IsNullOrWhiteSpace(packageVersion))
				{
					continue;
				}

				var packageKey = $"{packageId}@{packageVersion}";

				if (processedPackages.Contains(packageKey))
				{
					continue;
				}

				processedPackages.Add(packageKey);

				var assemblyPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(packageId, packageVersion);
				var signatureInfo = signatureService.ReadSignature(assemblyPath);
				var reputationInfo = await this.reputationService.GetReputationAsync(packageId, cancellationToken).ConfigureAwait(false);

				if (signatureInfo != null && signatureInfo.HasEmbeddedSignature && signatureInfo.IsSignatureValid)
				{
					var isMicrosoft = signatureInfo.Signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 ||
									signatureInfo.Subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;

					if (isMicrosoft)
					{
						if (processedSigners.Contains(signatureInfo.Thumbprint))
						{
							continue;
						}

						processedSigners.Add(signatureInfo.Thumbprint);

						var suggestion = new TrustSuggestion
						{
							IsSelected = true,
							Scope = TrustSuggestionScope.Signer,
							Subject = signatureInfo.Thumbprint,
							DisplayName = signatureInfo.Signer,
							RecommendationReason = "This package is signed by Microsoft Corporation with a valid Authenticode signature.",
							ReputationSourceDescription = "Verified Publisher (Microsoft)"
						};

						suggestion.Metadata["SignerThumbprint"] = signatureInfo.Thumbprint;
						suggestion.Metadata["SignerSubject"] = signatureInfo.Subject;
						suggestion.Metadata["SignerIssuer"] = signatureInfo.Issuer;
						suggestion.Metadata["SignerSerialNumber"] = signatureInfo.SerialNumber;
						suggestions.Add(suggestion);

						continue;
					}
				}

				if (reputationInfo != null && reputationInfo.IsVerified && reputationInfo.TotalDownloads >= 1000000)
				{
					var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
					var packageDir = Path.Combine(userHome, ".nuget", "packages", packageId.ToLowerInvariant(), packageVersion.ToLowerInvariant());
					var packageHash = TrustStoreService.CalculatePackageDirectoryHash(packageDir);

					if (!string.IsNullOrWhiteSpace(packageHash))
					{
						var suggestion = new TrustSuggestion
						{
							IsSelected = true,
							Scope = TrustSuggestionScope.Package,
							Subject = packageHash,
							DisplayName = $"{packageId} v{packageVersion}",
							RecommendationReason = $"Verified package on NuGet.org with very high download volume ({reputationInfo.TotalDownloads:N0} downloads).",
							ReputationSourceDescription = "Verified NuGet.org Publisher"
						};

						suggestion.Metadata["PackageId"] = packageId;
						suggestion.Metadata["PackageVersion"] = packageVersion;
						suggestion.Metadata["PackageHash"] = packageHash;
						suggestions.Add(suggestion);

						continue;
					}
				}

				if (signatureInfo != null && signatureInfo.HasEmbeddedSignature && signatureInfo.IsSignatureValid)
				{
					if (processedSigners.Contains(signatureInfo.Thumbprint))
					{
						continue;
					}

					processedSigners.Add(signatureInfo.Thumbprint);

					var suggestion = new TrustSuggestion
					{
						IsSelected = true,
						Scope = TrustSuggestionScope.Signer,
						Subject = signatureInfo.Thumbprint,
						DisplayName = signatureInfo.Signer,
						RecommendationReason = $"Signed by a valid certificate signer: '{signatureInfo.Signer}'.",
						ReputationSourceDescription = "Valid Authenticode Signer"
					};

					suggestion.Metadata["SignerThumbprint"] = signatureInfo.Thumbprint;
					suggestion.Metadata["SignerSubject"] = signatureInfo.Subject;
					suggestion.Metadata["SignerIssuer"] = signatureInfo.Issuer;
					suggestion.Metadata["SignerSerialNumber"] = signatureInfo.SerialNumber;
					suggestions.Add(suggestion);

					continue;
				}

				// If package did not meet high-trust signature or reputation thresholds, suggest it as an unselected suggestion so the user can manually choose to trust it.
				var fallbackUserHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
				var fallbackPackageDir = Path.Combine(fallbackUserHome, ".nuget", "packages", packageId.ToLowerInvariant(), packageVersion.ToLowerInvariant());
				var fallbackPackageHash = TrustStoreService.CalculatePackageDirectoryHash(fallbackPackageDir);

				if (!string.IsNullOrWhiteSpace(fallbackPackageHash))
				{
					var suggestion = new TrustSuggestion
					{
						IsSelected = false,
						Scope = TrustSuggestionScope.Package,
						Subject = fallbackPackageHash,
						DisplayName = $"{packageId} v{packageVersion}",
						RecommendationReason = "Unsigned package with no verified publisher identity. Review custom build tasks before trusting.",
						ReputationSourceDescription = "Unverified Publisher"
					};

					suggestion.Metadata["PackageId"] = packageId;
					suggestion.Metadata["PackageVersion"] = packageVersion;
					suggestion.Metadata["PackageHash"] = fallbackPackageHash;
					suggestions.Add(suggestion);
				}
			}

			return suggestions;
		}
	}
}
