using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
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
	[ProvideToolWindow(typeof(ToolWindows.ProjectSecurityReviewToolWindow), Style = VsDockStyle.MDI)]
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
			this.reviewSelectionService.ProjectReviewTargetPath = null;
			this.reviewSelectionService.SolutionReviewTargetPath = null;

			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var projectWindow = await this.GetProjectSecurityReviewToolWindowAsync(create: false);

			if (projectWindow != null)
			{
				projectWindow.ClearReport();
			}

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
			await Commands.OpenProjectSecurityReviewCommand.InitializeAsync(this);
			await Commands.OpenSolutionSecurityReviewCommand.InitializeAsync(this);
			await Commands.TrustCurrentProjectVersionCommand.InitializeAsync(this);
			await Commands.EditPolicyCommand.InitializeAsync(this);
			await Commands.CreateBaselineCommand.InitializeAsync(this);

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

			this.shieldStatusBarControl.UpdateState(this.latestScanReport);
		}

		/// <summary>
		/// Opens the Project Security Review tool window and loads a scan report.
		/// </summary>
		/// <param name="targetPath">Optional target path for the loaded report context.</param>
		/// <param name="report">Optional precomputed report; when null, a solution scan is executed.</param>
		/// <returns>A task that completes when the window has been updated.</returns>
		internal async Task ShowProjectSecurityReviewAsync(string? targetPath, Core.ScanReport? report)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			if (!Services.SolutionDiscoveryService.HasOpenSolution())
			{
				var existingWindow = await this.GetProjectSecurityReviewToolWindowAsync(create: false);

				if (existingWindow != null)
				{
					existingWindow.ClearReport();
				}

				await this.UiFeedbackService.WriteLineAsync("Project Security Review is unavailable because no solution is loaded.", CancellationToken.None);
				return;
			}

			await this.UiFeedbackService.WriteLineAsync("Opening Project Security Review tool window.", CancellationToken.None);

			var reviewWindow = await this.GetProjectSecurityReviewToolWindowAsync(create: true);

			if (reviewWindow == null)
			{
				throw new NotSupportedException("Cannot create Project Security Review tool window.");
			}

			if (report == null)
			{
				report = this.latestScanReport;
			}

			if (report == null)
			{
				var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);

				if (string.IsNullOrWhiteSpace(solutionPath) || !File.Exists(solutionPath))
				{
					await this.UiFeedbackService.WriteLineAsync("Project Security Review tool window opened without an available solution scan.", CancellationToken.None);
					return;
				}

				var solutionPathToScan = solutionPath!;

				await this.UiFeedbackService.WriteLineAsync($"Scanning current solution for Project Security Review: {solutionPathToScan}", CancellationToken.None);
				report = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(solutionPathToScan, DisposalToken);
				targetPath = solutionPathToScan;
				this.UpdateLatestScanReport(report);
			}

			var resolvedTargetPath = ResolveTargetPath(targetPath, report);
			this.reviewSelectionService.ProjectReviewTargetPath = resolvedTargetPath;
			await this.UiFeedbackService.WriteLineAsync($"Loaded Project Security Review report for {resolvedTargetPath}.", CancellationToken.None);
			reviewWindow.LoadReport(resolvedTargetPath, report);
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
		}

		/// <summary>
		/// Rescans the current target for Project Security Review.
		/// </summary>
		/// <returns>A task that completes when rescan and refresh operations finish.</returns>
		internal async Task RescanProjectSecurityReviewAsync()
		{
			if (!Services.SolutionDiscoveryService.HasOpenSolution())
			{
				await this.UiFeedbackService.WriteLineAsync("Project rescan skipped because no solution is loaded.", CancellationToken.None);
				return;
			}

			var targetPath = this.reviewSelectionService.ProjectReviewTargetPath;

			if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
			{
				targetPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this).ConfigureAwait(false);
			}

			if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
			{
				await this.UiFeedbackService.WriteLineAsync("Project rescan skipped because no valid scan target was available.", CancellationToken.None);
				return;
			}

			var scanPath = targetPath!;
			await this.UiFeedbackService.WriteLineAsync($"Rescanning Project Security Review target: {scanPath}", CancellationToken.None);
			var report = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(scanPath, DisposalToken);

			this.UpdateLatestScanReport(report);
			await this.ShowProjectSecurityReviewAsync(scanPath, report);
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
			var report             = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(solutionPathToScan, DisposalToken);

			this.UpdateLatestScanReport(report);
			await this.RefreshProjectSecurityReviewIfOpenAsync(solutionPathToScan, report);
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
				await this.JoinableTaskFactory.SwitchToMainThreadAsync(this.DisposalToken);

				var options = this.GetOptionsPage();

				if (Services.RiskEvaluationService.RequiresUserAttention(e) && options.AutoOpenSecurityReviewOnOpen)
				{
					if (!this.isInitialized)
					{
						await this.UiFeedbackService.WriteLineAsync("Project Security Review will be retried after package initialization completes.", CancellationToken.None);
						_ = this.RetryProjectSecurityReviewAsync(e);
						return;
					}

					await this.UiFeedbackService.WriteLineAsync("Opening Project Security Review because the scan requires user attention.", CancellationToken.None);
					await this.ShowProjectSecurityReviewAsync(e.Target.TargetPath, e);
				}
				else
				{
					if (Services.RiskEvaluationService.RequiresUserAttention(e) && !options.AutoOpenSecurityReviewOnOpen)
					{
						await this.UiFeedbackService.WriteLineAsync("Project Security Review auto-open is disabled by options.", CancellationToken.None);
					}

					await this.RefreshProjectSecurityReviewIfOpenAsync(e.Target.TargetPath, e);
				}

				await this.RefreshSolutionSecurityReviewIfOpenAsync(e.Target.TargetPath, e);
			});
		}

		/// <summary>
		/// Retries opening the Project Security Review window when initialization is delayed.
		/// </summary>
		/// <param name="report">The scan report that requires user attention.</param>
		/// <returns>A task that completes when retry processing finishes.</returns>
		private async Task RetryProjectSecurityReviewAsync(Core.ScanReport report)
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
					await this.UiFeedbackService.WriteLineAsync($"Opening Project Security Review after retry {attempt} because the scan requires user attention.", CancellationToken.None);
					await this.ShowProjectSecurityReviewAsync(report.Target.TargetPath, report);
				});

				return;
			}

			await this.UiFeedbackService.WriteLineAsync("Opening Project Security Review failed.", CancellationToken.None);
		}

		/// <summary>
		/// Gets the Project Security Review tool window instance.
		/// </summary>
		/// <param name="create"><c>true</c> to create the window when missing; otherwise <c>false</c>.</param>
		/// <returns>The tool window when available; otherwise <c>null</c>.</returns>
		private async Task<ToolWindows.ProjectSecurityReviewToolWindow?> GetProjectSecurityReviewToolWindowAsync(bool create)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var window = await ShowToolWindowAsync(typeof(ToolWindows.ProjectSecurityReviewToolWindow), 0, create, DisposalToken);

			if (window is not ToolWindows.ProjectSecurityReviewToolWindow reviewWindow || reviewWindow.Frame == null)
			{
				return null;
			}

			return reviewWindow;
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
		/// Refreshes Project Security Review content when the tool window is already open.
		/// </summary>
		/// <param name="targetPath">The scanned target path.</param>
		/// <param name="report">The scan report to load.</param>
		/// <returns>A task that completes when refresh processing finishes.</returns>
		private async Task RefreshProjectSecurityReviewIfOpenAsync(string targetPath, Core.ScanReport report)
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var reviewWindow = await this.GetProjectSecurityReviewToolWindowAsync(create: false);

			if (reviewWindow == null)
			{
				return;
			}

			var preferredReport = SelectPreferredReport(this.latestScanReport, report) ?? report;
			var preferredTargetPathInput = ReferenceEquals(preferredReport, report) ? targetPath : preferredReport.Target.TargetPath;
			var preferredTargetPath = ResolveTargetPath(preferredTargetPathInput, preferredReport);
			this.reviewSelectionService.ProjectReviewTargetPath = preferredTargetPath;

			reviewWindow.LoadReport(preferredTargetPath, preferredReport);
			await this.UiFeedbackService.WriteLineAsync($"Project Security Review refreshed for {preferredTargetPath}.", CancellationToken.None);
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
				return;
			}

			var preferredReport = SelectPreferredReport(this.latestScanReport, report) ?? report;
			var preferredTargetPathInput = ReferenceEquals(preferredReport, report) ? targetPath : preferredReport.Target.TargetPath;
			var preferredTargetPath = ResolveTargetPath(preferredTargetPathInput, preferredReport);
			this.reviewSelectionService.SolutionReviewTargetPath = preferredTargetPath;

			reviewWindow.LoadReport(preferredTargetPath, preferredReport);
			await this.UiFeedbackService.WriteLineAsync($"Solution Security Review refreshed for {preferredTargetPath}.", CancellationToken.None);
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

			var currentRank = GetRecommendedActionRank(current.RecommendedAction);
			var candidateRank = GetRecommendedActionRank(candidate.RecommendedAction);

			if (candidateRank > currentRank)
			{
				return candidate;
			}

			if (candidateRank < currentRank)
			{
				return current;
			}

			if (candidate.RiskScore > current.RiskScore)
			{
				return candidate;
			}

			if (candidate.RiskScore < current.RiskScore)
			{
				return current;
			}

			return candidate.CompletedAtUtc >= current.CompletedAtUtc ? candidate : current;
		}

		private static int GetRecommendedActionRank(Core.RecommendedAction action)
		{
			switch (action)
			{
				case Core.RecommendedAction.Block:
					return 3;
				case Core.RecommendedAction.RequireApproval:
					return 2;
				case Core.RecommendedAction.Warn:
					return 1;
				default:
					return 0;
			}
		}
	}
}
