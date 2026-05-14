using System;
using System.Security.Principal;
using System.Threading.Tasks;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.ToolWindows;

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

		/// <summary>
		/// Opens the trust assembly dialog and adds the assembly to the trust store if confirmed.
		/// </summary>
		/// <param name="finding">The finding whose owning assembly should be trusted.</param>
		/// <param name="reason">Reason provided by the user.</param>
		/// <returns>A task that completes when the dialog is closed.</returns>
		public async Task TrustAssemblyAsync(FindingViewModel finding, string reason)
		{
			if (finding == null)
			{
				throw new ArgumentNullException(nameof(finding));
			}

			if (string.IsNullOrWhiteSpace(finding.OwningAssembly))
			{
				throw new InvalidOperationException("Finding does not have an owning assembly.");
			}

			var dialog = new TrustAssemblyDialog
			{
				AssemblyName    = finding.OwningAssembly.Split('@')[0],
				AssemblyVersion = finding.OwningAssembly.Contains("@") ? finding.OwningAssembly.Split('@')[1] : "Unknown",
				AssemblyPath    = finding.FilePath,
				Owner           = System.Windows.Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner
			};

			var result = dialog.ShowDialog();

			if (result == true)
			{
				var trustPath = this.trustStoreService.GetDefaultUserTrustPath();
				var userSid  = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				this.trustStoreService.AddDecision(
					trustPath,
					new TrustDecisionEntry
					{
						DecisionId  = Guid.NewGuid().ToString("D"),
						Scope       = "Assembly",
						SubjectHash = finding.OwningAssembly,
						Decision    = "Trust",
						Reason      = reason,
						UserSid     = userSid,
						CreatedAtUtc = DateTimeOffset.UtcNow
					});
			}
		}
	}
}
