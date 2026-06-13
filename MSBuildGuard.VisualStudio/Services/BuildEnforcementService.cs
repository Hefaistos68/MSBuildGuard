using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Interop;
using EnvDTE;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using MSBuildGuard.Core;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Enforces MSBuild Guard policy decisions by canceling Visual Studio builds when user action is required.
	/// </summary>
	internal sealed class BuildEnforcementService : IVsUpdateSolutionEvents, IVsUpdateSolutionEvents2, IDisposable
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

				if (report == null || report.Target.TargetKind != TargetKind.Solution)
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
			}
			catch (Exception ex)
			{
				_ = this.package.UiFeedbackService.WriteLineAsync($"MSBuild Guard build scan initialization failed: {ex.Message}", CancellationToken.None);
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

		/// <inheritdoc />
		public int UpdateProjectCfg_Begin(IVsHierarchy pHierProj, IVsCfg pCfgProj, IVsCfg pCfgSln, uint dwAction, ref int pfCancel)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			try
			{
				pHierProj.GetProperty((uint)VSConstants.VSITEMID_ROOT, (int)__VSHPROPID.VSHPROPID_ExtObject, out var extObject);

				if (extObject is Project project && !string.IsNullOrWhiteSpace(project.FullName))
				{
					var projectPath = project.FullName;
					var report      = this.package.LatestScanReport;

					if (report == null)
					{
						return VSConstants.S_OK;
					}

					var solutionPath = SolutionDiscoveryService.GetOpenSolutionPath();
					var viewModel    = new MSBuildGuard.VisualStudio.ToolWindows.BuildBlockDialogViewModel(report, solutionPath, projectPath);

					if (!RiskEvaluationService.RequiresBuildBlock(viewModel))
					{
						return VSConstants.S_OK;
					}

					var dialog          = new MSBuildGuard.VisualStudio.ToolWindows.BuildBlockDialog(viewModel);
					var serviceProvider = (IServiceProvider)this.package;
					var uiShell         = serviceProvider.GetService(typeof(SVsUIShell)) as IVsUIShell;
					var ownerHandle     = IntPtr.Zero;

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
						_ = this.package.UiFeedbackService.WriteLineAsync($"Build of {project.Name} allowed by user override despite policy requiring action.", CancellationToken.None);

						return VSConstants.S_OK;
					}

					pfCancel = 1;
					_ = this.package.UiFeedbackService.WriteLineAsync($"Build of {project.Name} blocked by MSBuild Guard because policy requires user action.", CancellationToken.None);
				}
			}
			catch (Exception ex)
			{
				pfCancel = 1;
				_ = this.package.UiFeedbackService.WriteLineAsync($"Build blocked because MSBuild Guard project configuration enforcement failed: {ex.Message}", CancellationToken.None);
			}

			return VSConstants.S_OK;
		}

		/// <inheritdoc />
		public int UpdateProjectCfg_Done(IVsHierarchy pHierProj, IVsCfg pCfgProj, IVsCfg pCfgSln, uint dwAction, int fSuccess, int fModified)
		{
			return VSConstants.S_OK;
		}
	}
}
