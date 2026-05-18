using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.ComponentModelHost;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Task = System.Threading.Tasks.Task;

namespace MSBuildGuard.VisualStudio
{
	/// <summary>
	/// Package entry point for MSBuild Guard for Visual Studio.
	/// </summary>
	[PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
	[InstalledProductRegistration("MSBuild Guard for Visual Studio", "Project Security Review integration", "1.0")]
	[ProvideAutoLoad(VSConstants.UICONTEXT.ShellInitialized_string, PackageAutoLoadFlags.BackgroundLoad)]
	[ProvideToolWindow(typeof(ToolWindows.SolutionSecurityReviewToolWindow), Style = VsDockStyle.MDI)]
	[ProvideToolWindow(typeof(ToolWindows.PolicyEditorToolWindow), Style = VsDockStyle.MDI)]
	[ProvideOptionPage(typeof(Options.MSBuildGuardOptionsPage), "MSBuild Guard", "General", 0, 0, true)]
	[ProvideMenuResource("Menus.ctmenu", 1)]
	[Guid(PackageGuids.PackageString)]
	[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Disposed through the AsyncPackage disposal lifecycle.")]
	public sealed class MSBuildGuardPackage : AsyncPackage
	{
		/// <summary>
		/// Provides shared output window and status bar feedback operations.
		/// </summary>
		private readonly Services.VisualStudioUiFeedbackService uiFeedbackService;

		/// <summary>
		/// Stores the latest scan report used by UI surfaces.
		/// </summary>
		private Core.ScanReport? latestScanReport;

		/// <summary>
		/// Monitors NuGet restore activity and triggers rescans.
		/// </summary>
		private Services.NuGetRestoreMonitorService? nuGetRestoreMonitorService;

		/// <summary>
		/// Enforces policy-based build blocking during Visual Studio builds.
		/// </summary>
		private Services.BuildEnforcementService? buildEnforcementService;

		/// <summary>
		/// Stores current review selections for rescan operations.
		/// </summary>
		private readonly Services.SolutionReviewSelectionService reviewSelectionService = new Services.SolutionReviewSelectionService();

		/// <summary>
		/// Hosts the security shield control shown in the status bar.
		/// </summary>
		private Services.ShieldStatusBarControl? shieldStatusBarControl;

		/// <summary>
		/// Monitors solution events and publishes scan completion callbacks.
		/// </summary>
		private Services.SolutionMonitorService? solutionMonitorService;

		/// <summary>
		/// Indicates whether package initialization has completed.
		/// </summary>
		private bool isInitialized;

		/// <summary>
		/// Gets the active package instance.
		/// </summary>
		internal static MSBuildGuardPackage? Instance { get; private set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="MSBuildGuardPackage"/> class.
		/// </summary>
		public MSBuildGuardPackage()
		{
			Instance = this;
			this.uiFeedbackService = new Services.VisualStudioUiFeedbackService(this);
		}

		/// <summary>
		/// Gets the shared Visual Studio UI feedback service.
		/// </summary>
		internal Services.VisualStudioUiFeedbackService UiFeedbackService
		{
			get
			{
				return this.uiFeedbackService;
			}
		}

		/// <summary>
		/// Gets the persisted MSBuild Guard options page.
		/// </summary>
		/// <returns>The options page instance.</returns>
		internal Options.MSBuildGuardOptionsPage GetOptionsPage()
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			var page = (Options.MSBuildGuardOptionsPage)this.GetDialogPage(typeof(Options.MSBuildGuardOptionsPage));

			return page;
		}

		/// <summary>
		/// Gets the shared MEF component model.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The component model service.</returns>
		internal async Task<IComponentModel?> GetComponentModelAsync(CancellationToken cancellationToken)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			return await this.GetServiceAsync(typeof(SComponentModel)) as IComponentModel;
		}

		/// <summary>
		/// Gets the latest scan report.
		/// </summary>
		internal Core.ScanReport? LatestScanReport
		{
			get
			{
				return this.latestScanReport;
			}
		}

		/// <summary>
		/// Clears scan state and review surfaces after the active solution is unloaded.
		/// </summary>
		/// <returns>A task that completes when cleanup finishes.</returns>
		internal async Task OnSolutionUnloadedAsync()
		{
			await this.UiFeedbackService.WriteLineAsync("Solution unloaded. Clearing scan and review state.", CancellationToken.None);
			this.latestScanReport = null;
			this.reviewSelectionService.SolutionReviewTargetPath = null;

			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var solutionWindow = await this.GetSolutionSecurityReviewToolWindowAsync(create: false);

			if (solutionWindow != null)
			{
				solutionWindow.ClearReport();
			}

			await this.RefreshStatusBarShieldAsync();
		}

		/// <summary>
		/// Updates the latest scan report and refreshes command UI.
		/// </summary>
		/// <param name="report">The latest scan report.</param>
		internal void UpdateLatestScanReport(Core.ScanReport? report)
		{
			this.latestScanReport = SelectPreferredReport(this.latestScanReport, report);
			this.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.RefreshStatusBarShieldAsync().ConfigureAwait(false);
			}).FileAndForget(nameof(MSBuildGuardPackage));
		}

		/// <summary>
		/// Initializes package services and commands.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <param name="progress">Progress reporter.</param>
		/// <returns>A task that completes when package initialization finishes.</returns>
		protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			await this.UiFeedbackService.WriteLineAsync("MSBuild Guard package initialized.", cancellationToken);
			await Commands.ScanSolutionCommand.InitializeAsync(this);
			await Commands.OpenSolutionSecurityReviewCommand.InitializeAsync(this);
			await Commands.TrustCurrentProjectVersionCommand.InitializeAsync(this);
			await Commands.EditPolicyCommand.InitializeAsync(this);
			await Commands.CreateBaselineCommand.InitializeAsync(this);
			await Commands.ManageAssemblyTrustsCommand.InitializeAsync(this);
			await Commands.ManageSignerTrustsCommand.InitializeAsync(this);

			this.shieldStatusBarControl = new Services.ShieldStatusBarControl(this);
			this.shieldStatusBarControl.UpdateState(this.latestScanReport);
			_ = Services.StatusBarInjector.InjectControlAsync(this.shieldStatusBarControl);

			this.solutionMonitorService = new Services.SolutionMonitorService(this);
			this.solutionMonitorService.ScanCompleted += this.OnSolutionScanCompleted;

			this.nuGetRestoreMonitorService = new Services.NuGetRestoreMonitorService(this);
			this.buildEnforcementService = new Services.BuildEnforcementService(this);

			_ = this.StartMonitorsAsync(cancellationToken);
			this.isInitialized = true;
		}

		/// <summary>
		/// Releases managed resources owned by the package.
		/// </summary>
		/// <param name="disposing"><c>true</c> when disposing managed resources; otherwise <c>false</c>.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (this.buildEnforcementService != null)
				{
					this.buildEnforcementService.Dispose();
					this.buildEnforcementService = null;
				}

				if (this.nuGetRestoreMonitorService != null)
				{
					this.nuGetRestoreMonitorService.Dispose();
					this.nuGetRestoreMonitorService = null;
				}

				if (this.solutionMonitorService != null)
				{
					this.solutionMonitorService.ScanCompleted -= this.OnSolutionScanCompleted;
					this.solutionMonitorService.Dispose();
					this.solutionMonitorService = null;
				}

				this.uiFeedbackService.Dispose();
			}

			base.Dispose(disposing);
		}

		/// <summary>
		/// Starts background monitor services used by the extension.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A task that completes after startup attempts finish.</returns>
		private async Task StartMonitorsAsync(CancellationToken cancellationToken)
		{
			try
			{
				await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

				var options = this.GetOptionsPage();

				if (this.solutionMonitorService != null)
				{
					await this.solutionMonitorService.StartAsync(cancellationToken);
				}

				if (this.nuGetRestoreMonitorService != null && options.ScanNuGetPackages)
				{
					await this.nuGetRestoreMonitorService.StartAsync(cancellationToken);
				}
				else if (this.nuGetRestoreMonitorService != null)
				{
					await this.UiFeedbackService.WriteLineAsync("NuGet restore monitor disabled by options.", CancellationToken.None);
				}

				if (this.buildEnforcementService != null)
				{
					await this.buildEnforcementService.StartAsync(cancellationToken);
				}
			}
			catch (Exception ex)
			{
				await this.UiFeedbackService.WriteLineAsync($"Monitor startup failed: {ex.Message}", CancellationToken.None);
			}
		}

		/// <summary>
		/// Refreshes the status bar shield control with the latest report state.
		/// </summary>
		/// <returns>A task that completes when the UI has been updated.</returns>
		private async Task RefreshStatusBarShieldAsync()
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			if (this.shieldStatusBarControl == null)
			{
				return;
			}

			int? effectiveRiskScore = null;

			if (this.latestScanReport != null)
			{
				effectiveRiskScore = GetEffectiveRiskScore(this.latestScanReport);
			}

			this.shieldStatusBarControl.UpdateState(this.latestScanReport, effectiveRiskScore);
		}

		/// <summary>
		/// Opens the Solution Security Review tool window and loads a solution scan report.
		/// </summary>
		/// <param name="solutionPath">Optional solution path for loaded context.</param>
		/// <param name="report">Optional precomputed report; when null, a solution scan is executed.</param>
		/// <returns>A task that completes when the window has been updated.</returns>
		internal async Task ShowSolutionSecurityReviewAsync(string? solutionPath, Core.ScanReport? report)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			if (!Services.SolutionDiscoveryService.HasOpenSolution())
			{
				var existingWindow = await this.GetSolutionSecurityReviewToolWindowAsync(create: false);

				if (existingWindow != null)
				{
					existingWindow.ClearReport();
				}

				await this.UiFeedbackService.WriteLineAsync("Solution Security Review is unavailable because no solution is loaded.", CancellationToken.None);
				return;
			}

			await this.UiFeedbackService.WriteLineAsync("Opening Solution Security Review tool window.", CancellationToken.None);

			var reviewWindow = await this.GetSolutionSecurityReviewToolWindowAsync(create: true);

			if (reviewWindow == null)
			{
				throw new NotSupportedException("Cannot create Solution Security Review tool window.");
			}

			if (report == null)
			{
				report = this.latestScanReport;
			}

			if (report != null && report.Target.TargetKind != Core.TargetKind.Solution)
			{
				await this.UiFeedbackService.WriteLineAsync($"[Flow] ShowSolutionSecurityReviewAsync ignored non-solution report target='{report.Target.TargetPath}', kind={report.Target.TargetKind}.", CancellationToken.None);
				report = null;
			}

			if (report == null)
			{
				var discoveredSolutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);

				if (string.IsNullOrWhiteSpace(discoveredSolutionPath) || !File.Exists(discoveredSolutionPath))
				{
					await this.UiFeedbackService.WriteLineAsync("Solution Security Review tool window opened without an available solution scan.", CancellationToken.None);
					return;
				}

				var solutionPathToScan = discoveredSolutionPath!;

				await this.UiFeedbackService.WriteLineAsync($"Scanning current solution for Solution Security Review: {solutionPathToScan}", CancellationToken.None);
				report = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(solutionPathToScan, DisposalToken);
				solutionPath = solutionPathToScan;
				this.UpdateLatestScanReport(report);
			}

			var resolvedTargetPath = ResolveTargetPath(solutionPath, report);
			this.reviewSelectionService.SolutionReviewTargetPath = resolvedTargetPath;
			await this.UiFeedbackService.WriteLineAsync($"Loaded Solution Security Review report for {resolvedTargetPath}.", CancellationToken.None);
			reviewWindow.LoadReport(resolvedTargetPath, report);
			await this.RefreshStatusBarShieldAsync();
		}

		/// <summary>
		/// Rescans the current solution target for Solution Security Review.
		/// </summary>
		/// <returns>A task that completes when rescan and refresh operations finish.</returns>
		internal async Task RescanSolutionSecurityReviewAsync()
		{
			if (!Services.SolutionDiscoveryService.HasOpenSolution())
			{
				await this.UiFeedbackService.WriteLineAsync("Solution rescan skipped because no solution is loaded.", CancellationToken.None);
				return;
			}

			var targetPath = this.reviewSelectionService.SolutionReviewTargetPath;

			if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
			{
				targetPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this).ConfigureAwait(false);
			}

			if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
			{
				await this.UiFeedbackService.WriteLineAsync("Solution rescan skipped because no open solution was available.", CancellationToken.None);
				return;
			}

			var scanPath = targetPath!;
			await this.UiFeedbackService.WriteLineAsync($"Rescanning Solution Security Review target: {scanPath}", CancellationToken.None);
			var report = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(scanPath, DisposalToken);

			this.UpdateLatestScanReport(report);
			await this.ShowSolutionSecurityReviewAsync(scanPath, report);
		}

		/// <summary>
		/// Rescans the open solution after policy changes and refreshes relevant UI surfaces.
		/// </summary>
		internal async Task OnPolicyChangedRescanAsync()
		{
			await this.UiFeedbackService.WriteLineAsync("Policy changed. Rescanning solution.", CancellationToken.None);

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);

			if (string.IsNullOrWhiteSpace(solutionPath) || !File.Exists(solutionPath))
			{
				await this.UiFeedbackService.WriteLineAsync("Policy changed but no open solution was available to rescan.", CancellationToken.None);
				return;
			}

			var solutionPathToScan = solutionPath!;
			var report = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(solutionPathToScan, DisposalToken);

			this.UpdateLatestScanReport(report);
			await this.RefreshSolutionSecurityReviewIfOpenAsync(solutionPathToScan, report);
		}

		/// <summary>
		/// Opens the Policy Editor tool window for the current context.
		/// </summary>
		internal async Task ShowPolicyEditorAsync(ToolWindows.PolicyEditorViewModel.PolicyScopeType? preferredPolicyType = null)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);
			var loadedProjectPaths = Services.SolutionExplorerProjectDiscoveryService.GetLoadedProjectPaths();

			var window = await ShowToolWindowAsync(typeof(ToolWindows.PolicyEditorToolWindow), 0, true, DisposalToken);

			if (window is not ToolWindows.PolicyEditorToolWindow editorWindow)
			{
				throw new NotSupportedException("Cannot create Policy Editor tool window.");
			}

			editorWindow.LoadPolicyContext(solutionPath ?? string.Empty, loadedProjectPaths, preferredPolicyType);
			await this.UiFeedbackService.WriteLineAsync("Policy Editor opened.", CancellationToken.None);
		}

		/// <summary>
		/// Opens the Manage Assembly Trusts dialog for managing global assembly trust decisions.
		/// </summary>
		/// <returns>A task that completes when the dialog is closed.</returns>
		internal async Task ShowManageAssemblyTrustsAsync()
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var dialog = new ToolWindows.ManageAssemblyTrustsDialog
			{
				Owner = Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner
			};

			var result = dialog.ShowDialog();

			if (result == true)
			{
				var solutionWindow = await this.GetSolutionSecurityReviewToolWindowAsync(create: false);

				if (solutionWindow?.Content is ToolWindows.SolutionSecurityReviewControl solutionControl)
				{
					await this.RescanSolutionSecurityReviewAsync();
				}
			}

			await this.UiFeedbackService.WriteLineAsync("Manage Assembly Trusts dialog closed.", CancellationToken.None);
		}

		/// <summary>
		/// Opens the Manage Signer Trusts dialog for managing trusted certificate signers.
		/// </summary>
		/// <returns>A task that completes when the dialog is closed.</returns>
		internal async Task ShowManageSignerTrustsAsync()
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var dialog = new ToolWindows.ManageSignerTrustsDialog
			{
				Owner = Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner
			};

			var result = dialog.ShowDialog();

			if (result == true)
			{
				var solutionWindow = await this.GetSolutionSecurityReviewToolWindowAsync(create: false);

				if (solutionWindow?.Content is ToolWindows.SolutionSecurityReviewControl)
				{
					await this.RescanSolutionSecurityReviewAsync();
				}
			}

			await this.UiFeedbackService.WriteLineAsync("Manage Signer Trusts dialog closed.", CancellationToken.None);
		}

		/// <summary>
		/// Handles solution scan completion and updates related UI surfaces.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Completed scan report.</param>
		private void OnSolutionScanCompleted(object? sender, Core.ScanReport e)
		{
			this.UpdateLatestScanReport(e);
			_ = this.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.UiFeedbackService.WriteLineAsync($"Solution scan completed: {e.Target.TargetPath}", CancellationToken.None);
				await this.UiFeedbackService.WriteLineAsync($"[Flow] OnSolutionScanCompleted targetKind={e.Target.TargetKind}, findings={e.Findings.Count}", CancellationToken.None);
				await this.JoinableTaskFactory.SwitchToMainThreadAsync(this.DisposalToken);

				var options = this.GetOptionsPage();

				if (Services.RiskEvaluationService.RequiresUserAttention(e) && options.AutoOpenSecurityReviewOnOpen)
				{
					if (!this.isInitialized)
					{
						await this.UiFeedbackService.WriteLineAsync("Solution Security Review will be retried after package initialization completes.", CancellationToken.None);
						_ = this.RetrySolutionSecurityReviewAsync(e);
						return;
					}

					await this.UiFeedbackService.WriteLineAsync("Opening Solution Security Review because the scan requires user attention.", CancellationToken.None);
					await this.ShowSolutionSecurityReviewAsync(e.Target.TargetPath, e);
				}
				else if (Services.RiskEvaluationService.RequiresUserAttention(e) && !options.AutoOpenSecurityReviewOnOpen)
				{
					await this.UiFeedbackService.WriteLineAsync("Solution Security Review auto-open is disabled by options.", CancellationToken.None);
				}

				await this.RefreshSolutionSecurityReviewIfOpenAsync(e.Target.TargetPath, e);
			});
		}

		/// <summary>
		/// Retries opening the Solution Security Review window when initialization is delayed.
		/// </summary>
		/// <param name="report">The scan report that requires user attention.</param>
		/// <returns>A task that completes when retry processing finishes.</returns>
		private async Task RetrySolutionSecurityReviewAsync(Core.ScanReport report)
		{
			for (var attempt = 1; attempt <= 3; attempt++)
			{
				try
				{
					await Task.Delay(TimeSpan.FromSeconds(1), DisposalToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					return;
				}

				if (!this.isInitialized)
				{
					continue;
				}

				if (!Services.RiskEvaluationService.RequiresUserAttention(report))
				{
					return;
				}

				await this.JoinableTaskFactory.RunAsync(async delegate
				{
					await this.UiFeedbackService.WriteLineAsync($"Opening Solution Security Review after retry {attempt} because the scan requires user attention.", CancellationToken.None);
					await this.ShowSolutionSecurityReviewAsync(report.Target.TargetPath, report);
				});

				return;
			}

			await this.UiFeedbackService.WriteLineAsync("Opening Solution Security Review failed.", CancellationToken.None);
		}

		/// <summary>
		/// Gets the Solution Security Review tool window instance.
		/// </summary>
		/// <param name="create"><c>true</c> to create the window when missing; otherwise <c>false</c>.</param>
		/// <returns>The tool window when available; otherwise <c>null</c>.</returns>
		private async Task<ToolWindows.SolutionSecurityReviewToolWindow?> GetSolutionSecurityReviewToolWindowAsync(bool create)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var window = await ShowToolWindowAsync(typeof(ToolWindows.SolutionSecurityReviewToolWindow), 0, create, DisposalToken);

			if (window is not ToolWindows.SolutionSecurityReviewToolWindow reviewWindow || reviewWindow.Frame == null)
			{
				return null;
			}

			return reviewWindow;
		}

		/// <summary>
		/// Refreshes Solution Security Review content when the tool window is already open.
		/// </summary>
		/// <param name="targetPath">The scanned target path.</param>
		/// <param name="report">The scan report to load.</param>
		/// <returns>A task that completes when refresh processing finishes.</returns>
		private async Task RefreshSolutionSecurityReviewIfOpenAsync(string targetPath, Core.ScanReport report)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var reviewWindow = await this.GetSolutionSecurityReviewToolWindowAsync(create: false);

			if (reviewWindow == null)
			{
				await this.UiFeedbackService.WriteLineAsync("[Flow] RefreshSolutionSecurityReviewIfOpenAsync skipped because window is not open.", CancellationToken.None);
				return;
			}

			await this.UiFeedbackService.WriteLineAsync($"[Flow] RefreshSolutionSecurityReviewIfOpenAsync received report target='{report.Target.TargetPath}', kind={report.Target.TargetKind}, findings={report.Findings.Count}", CancellationToken.None);
			// If the report is for a project (not a solution), trigger a full solution rescan
			// to ensure the solution review shows aggregated findings from all projects
			if (report.Target.TargetKind != Core.TargetKind.Solution)
			{
				await this.UiFeedbackService.WriteLineAsync("[Flow] RefreshSolutionSecurityReviewIfOpenAsync received non-solution report; requesting solution-wide rescan.", CancellationToken.None);
				var discoveredSolutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);

				if (!string.IsNullOrWhiteSpace(discoveredSolutionPath) && File.Exists(discoveredSolutionPath))
				{
					await this.UiFeedbackService.WriteLineAsync($"Rescanning solution for Solution Security Review: {discoveredSolutionPath}", CancellationToken.None);
					var solutionReport = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(discoveredSolutionPath, DisposalToken);
					this.UpdateLatestScanReport(solutionReport);
					reviewWindow.LoadReport(discoveredSolutionPath, solutionReport);
					await this.UiFeedbackService.WriteLineAsync($"Solution Security Review refreshed for {discoveredSolutionPath}.", CancellationToken.None);
				}

				return;
			}

			// Use the most recently completed report for display, ensuring the window always shows current scan results
			var resolvedTargetPath = ResolveTargetPath(targetPath, report);
			this.reviewSelectionService.SolutionReviewTargetPath = resolvedTargetPath;

			await this.UiFeedbackService.WriteLineAsync($"[Flow] RefreshSolutionSecurityReviewIfOpenAsync loading window with resolvedTarget='{resolvedTargetPath}'.", CancellationToken.None);
			reviewWindow.LoadReport(resolvedTargetPath, report);
			await this.RefreshStatusBarShieldAsync();
			await this.UiFeedbackService.WriteLineAsync($"Solution Security Review refreshed for {resolvedTargetPath}.", CancellationToken.None);
		}

		private static string ResolveTargetPath(string? targetPath, Core.ScanReport report)
		{
			if (!string.IsNullOrWhiteSpace(targetPath))
			{
				return targetPath;
			}

			if (!string.IsNullOrWhiteSpace(report.Target.TargetPath))
			{
				return report.Target.TargetPath;
			}

			return "Unknown target";
		}

		private static int GetEffectiveRiskScore(Core.ScanReport report)
		{
			var buildBlockViewModel = new ToolWindows.BuildBlockDialogViewModel(report);

			return buildBlockViewModel.RiskScore;
		}

		private static Core.ScanReport? SelectPreferredReport(Core.ScanReport? current, Core.ScanReport? candidate)
		{
			if (candidate == null)
			{
				return current;
			}

			if (current == null)
			{
				return candidate;
			}

			return candidate.CompletedAtUtc >= current.CompletedAtUtc ? candidate : current;
		}
	}
}
