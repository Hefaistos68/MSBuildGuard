using System;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Persists trust decisions from Visual Studio actions.
	/// </summary>
	internal sealed class VisualStudioTrustDecisionService
	{
		private readonly TrustStoreService trustStoreService;

		/// <summary>
		/// Initializes a new instance of the <see cref="VisualStudioTrustDecisionService"/> class.
		/// </summary>
		public VisualStudioTrustDecisionService()
		{
			this.trustStoreService = new TrustStoreService();
		}

		/// <summary>
		/// Trusts a single finding until file content changes.
		/// </summary>
		/// <param name="report">The report that contains the finding.</param>
		/// <param name="finding">The finding to trust.</param>
		/// <param name="reason">Reason provided by the user.</param>
		public void TrustUntilChanged(ScanReport report, FindingViewModel finding, string reason)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (finding == null)
			{
				throw new ArgumentNullException(nameof(finding));
			}

			var trustPath = this.trustStoreService.GetDefaultUserTrustPath();

			if (string.IsNullOrWhiteSpace(finding.Fingerprint))
			{
				throw new InvalidOperationException("Only findings with a fingerprint can be trusted.");
			}

			this.trustStoreService.AddDecision(
				trustPath,
				new TrustDecisionEntry
				{
					DecisionId      = Guid.NewGuid().ToString("D"),
					Scope           = "Finding",
					SubjectHash     = finding.Fingerprint,
					Decision        = "TrustUntilChanged",
					Reason          = reason,
					UserSid         = Environment.UserName,
					CreatedAtUtc    = DateTimeOffset.UtcNow,
					RepositoryRemote = report.Target.TrustContext.RepositoryRemote,
					Branch          = report.Target.TrustContext.Branch,
					CommitSha       = report.Target.TrustContext.CommitSha,
					PolicyProfile   = report.PolicyProfile
				});
		}

		/// <summary>
		/// Removes trust decisions for a single finding fingerprint.
		/// </summary>
		/// <param name="finding">The finding to untrust.</param>
		/// <param name="reason">Reason provided by the user.</param>
		/// <returns>The number of removed trust decisions.</returns>
		public int RemoveTrust(FindingViewModel finding, string reason)
		{
			if (finding == null)
			{
				throw new ArgumentNullException(nameof(finding));
			}

			if (string.IsNullOrWhiteSpace(finding.Fingerprint))
			{
				return 0;
			}

			var trustPath = this.trustStoreService.GetDefaultUserTrustPath();

			return this.trustStoreService.RemoveDecisionsBySubject(trustPath, finding.Fingerprint, reason, Environment.UserName);
		}
	}
}
