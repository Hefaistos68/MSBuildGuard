using System;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
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
					DecisionId       = Guid.NewGuid().ToString("D"),
					Scope            = "Finding",
					SubjectHash      = finding.Fingerprint,
					Decision         = "TrustUntilChanged",
					Reason           = reason,
					UserSid          = Environment.UserName,
					CreatedAtUtc     = DateTimeOffset.UtcNow,
					RepositoryRemote = report.Target.TrustContext.RepositoryRemote,
					Branch           = report.Target.TrustContext.Branch,
					CommitSha        = report.Target.TrustContext.CommitSha,
					PolicyProfile    = report.PolicyProfile
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

			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			var split = finding.OwningAssembly.Split('@');
			var assemblyName = split.Length > 0 ? split[0] : finding.OwningAssembly;
			var assemblyVersion = split.Length > 1 ? split[1] : "Unknown";
			var solutionPath = await SolutionDiscoveryService.GetOpenSolutionPathAsync(MSBuildGuardPackage.Instance!);
			var projectPath = SolutionExplorerProjectDiscoveryService.GetSelectedProjectPath() ?? string.Empty;
			var assemblyPath = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion)
				? AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion)
				: AssemblySignatureService.ResolveAssemblyFilePath(finding.FilePath);

			var dialog = new TrustAssemblyDialog
			{
				AssemblyName           = assemblyName,
				AssemblyVersion        = assemblyVersion,
				AssemblyPath           = assemblyPath,
				SolutionPath           = solutionPath ?? string.Empty,
				ProjectPath            = projectPath,
				Owner                  = System.Windows.Application.Current.MainWindow,
				WindowStartupLocation  = System.Windows.WindowStartupLocation.CenterOwner
			};

			if (dialog.ShowDialog() != true)
			{
				return;
			}

			var trustPath = ResolveTrustStorePath(dialog.SelectedScope, solutionPath ?? string.Empty, projectPath);
			var userSid = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";
			var trustReason = !string.IsNullOrWhiteSpace(dialog.TrustReason) ? dialog.TrustReason : reason;

			this.trustStoreService.AddAssemblyTrust(
				trustPath,
				assemblyName,
				assemblyVersion,
				trustReason,
				userSid,
				dialog.AssemblySigner,
				dialog.AssemblyIssuer,
				dialog.AssemblySubject,
				dialog.ExpiresAtUtc);
		}

		private string ResolveTrustStorePath(TrustScope selectedScope, string solutionPath, string projectPath)
		{
			if (selectedScope == TrustScope.Project && !string.IsNullOrWhiteSpace(projectPath))
			{
				return this.trustStoreService.GetProjectTrustPath(projectPath);
			}

			if (selectedScope == TrustScope.Solution && !string.IsNullOrWhiteSpace(solutionPath))
			{
				return this.trustStoreService.GetSolutionTrustPath(solutionPath);
			}

			return this.trustStoreService.GetDefaultUserTrustPath();
		}
	}
}
