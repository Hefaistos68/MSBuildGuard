using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Interop;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Enforces MSBuild Guard policy decisions by canceling Visual Studio builds when user action is required.
	/// </summary>
	internal sealed class BuildEnforcementService : IVsUpdateSolutionEvents, IDisposable
	{
		private readonly MSBuildGuardPackage package;
		private readonly VisualStudioScannerService scannerService;

		private IVsSolutionBuildManager2? solutionBuildManager;
		private uint solutionBuildEventsCookie;
		private bool isStarted;

		/// <summary>
		/// Initializes a new instance of the <see cref="BuildEnforcementService"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		public BuildEnforcementService(MSBuildGuardPackage package)
		{
			this.package = package;
			this.scannerService = new VisualStudioScannerService(package);
		}

		/// <summary>
		/// Starts build enforcement by subscribing to Visual Studio solution build events.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A task that completes when startup finishes.</returns>
		public async Task StartAsync(CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			if (this.isStarted)
			{
				return;
			}

			this.solutionBuildManager = await this.package.GetServiceAsync(typeof(SVsSolutionBuildManager)) as IVsSolutionBuildManager2;

			if (this.solutionBuildManager == null)
			{
				await this.package.UiFeedbackService.WriteLineAsync("Build enforcement unavailable: solution build manager service not found.", CancellationToken.None);
				return;
			}

			ErrorHandler.ThrowOnFailure(this.solutionBuildManager.AdviseUpdateSolutionEvents(this, out this.solutionBuildEventsCookie));
			this.isStarted = true;
			await this.package.UiFeedbackService.WriteLineAsync("Build enforcement started.", CancellationToken.None);
		}

		/// <summary>
		/// Releases build-event subscriptions.
		/// </summary>
		public void Dispose()
		{
			ThreadHelper.JoinableTaskFactory.Run(async delegate
			{
				await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

				if (this.solutionBuildManager != null && this.solutionBuildEventsCookie != 0)
				{
					this.solutionBuildManager.UnadviseUpdateSolutionEvents(this.solutionBuildEventsCookie);
				}

				this.solutionBuildEventsCookie = 0;
				this.solutionBuildManager = null;
				this.isStarted = false;
			});
		}

		/// <inheritdoc />
		public int UpdateSolution_Begin(ref int pfCancelUpdate)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			try
			{
				var report = this.package.LatestScanReport;

				if (report == null)
				{
					var scanPath = this.package.JoinableTaskFactory.Run(async delegate
					{
						return await SolutionDiscoveryService.GetOpenSolutionPathAsync(this.package).ConfigureAwait(true);
					});

					if (!string.IsNullOrWhiteSpace(scanPath))
					{
						report = this.package.JoinableTaskFactory.Run(async delegate
						{
							return await this.scannerService.ScanSolutionAsync(scanPath, this.package.DisposalToken).ConfigureAwait(true);
						});
						this.package.UpdateLatestScanReport(report);
					}
				}

				if (!RiskEvaluationService.RequiresBuildBlock(report!))
					{
						return VSConstants.S_OK;
					}

					var viewModel = new MSBuildGuard.VisualStudio.ToolWindows.BuildBlockDialogViewModel(report!);
					var dialog = new MSBuildGuard.VisualStudio.ToolWindows.BuildBlockDialog(viewModel);
					var serviceProvider = (IServiceProvider)this.package;
					var uiShell = serviceProvider.GetService(typeof(SVsUIShell)) as IVsUIShell;
					IntPtr ownerHandle = IntPtr.Zero;

					if (uiShell != null)
					{
						ErrorHandler.ThrowOnFailure(uiShell.GetDialogOwnerHwnd(out ownerHandle));
					}

					if (ownerHandle != IntPtr.Zero)
					{
						new WindowInteropHelper(dialog).Owner = ownerHandle;
					}

					dialog.ShowDialog();

					if (dialog.UserChoseToProceed)
					{
						_ = this.package.UiFeedbackService.WriteLineAsync("Build allowed by user override despite policy requiring action.", CancellationToken.None);
						return VSConstants.S_OK;
					}

					pfCancelUpdate = 1;
					_ = this.package.UiFeedbackService.WriteLineAsync("Build blocked by MSBuild Guard because policy requires user action.", CancellationToken.None);
			}
			catch (Exception ex)
			{
				pfCancelUpdate = 1;
				_ = this.package.UiFeedbackService.WriteLineAsync($"Build blocked because MSBuild Guard enforcement failed: {ex.Message}", CancellationToken.None);
			}

			return VSConstants.S_OK;
		}

		/// <inheritdoc />
		public int UpdateSolution_Cancel()
		{
			return VSConstants.S_OK;
		}

		/// <inheritdoc />
		public int OnActiveProjectCfgChange(IVsHierarchy pIVsHierarchy)
		{
			return VSConstants.S_OK;
		}

		/// <inheritdoc />
		public int UpdateSolution_Done(int fSucceeded, int fModified, int fCancelCommand)
		{
			return VSConstants.S_OK;
		}

		/// <inheritdoc />
		public int UpdateSolution_StartUpdate(ref int pfCancelUpdate)
		{
			return VSConstants.S_OK;
		}
	}
}
