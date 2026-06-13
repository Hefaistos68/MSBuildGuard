using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.ComponentModelHost;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Microsoft.VisualStudio.Threading;
using MSBuildGuard.VisualStudio.Options;
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
	[ProvideOptionPage(typeof(Options.MSBuildGuardOptionsPage), "MSBuild Guard", "General", 0, 0, true, IsInUnifiedSettings = true)]
	[ProvideSettingsManifest(PackageRelativeManifestFile = "UnifiedSettings\\msbuildguard.registration.json")]
	[ProvideMenuResource("Menus.ctmenu", 1)]
	[Guid(PackageGuids.PackageString)]
	[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Disposed through the AsyncPackage disposal lifecycle.")]
	public sealed class MSBuildGuardPackage : AsyncPackage
	{
		/// <summary>
		/// Provides shared output window and status bar feedback operations.
		/// </summary>
		private readonly Services.VisualStudioUiFeedbackService uiFeedbackService;
		private readonly Services.GitIgnoreTrustSharingService gitIgnoreTrustSharingService = new Services.GitIgnoreTrustSharingService();
		private readonly Options.UnifiedSettingsOptionsProvider unifiedSettingsOptionsProvider = new Options.UnifiedSettingsOptionsProvider();

		/// <summary>
		/// Stores the latest scan report used by UI surfaces.
		/// </summary>
		private Core.ScanReport? latestScanReport;

		private bool isLatestReportGreen;
		private int latestReportEffectiveRiskScore;

		/// <summary>
		/// Gets a value indicating whether the current solution security is green (effective recommended action is Allow).
		/// </summary>
		internal bool IsLatestReportGreen => this.isLatestReportGreen;

		/// <summary>
		/// Gets the cached effective risk score for the latest scan report.
		/// </summary>
		internal int LatestReportEffectiveRiskScore => this.latestReportEffectiveRiskScore;

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
		/// Tracks solution paths for which baseline onboarding has been prompted during this session.
		/// </summary>
		private readonly System.Collections.Generic.HashSet<string> promptedSolutions = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
		/// Gets the current runtime options from unified settings storage.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The current options snapshot.</returns>
		internal async Task<Options.MSBuildGuardOptionsSnapshot> GetOptionsSnapshotAsync(CancellationToken cancellationToken)
		{
			return await this.unifiedSettingsOptionsProvider.GetSnapshotAsync(this, cancellationToken);
		}

		/// <summary>
		/// Notifies the options storage that settings were updated.
		/// </summary>
		internal void NotifyOptionsChanged()
		{
			this.unifiedSettingsOptionsProvider.NotifyChanged();
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
				await this.RecalculateEffectiveRiskAsync().ConfigureAwait(false);
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
			await Commands.ManagePackageTrustsCommand.InitializeAsync(this);

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

				this.unifiedSettingsOptionsProvider.Dispose();
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

				var options = await this.GetOptionsSnapshotAsync(cancellationToken).ConfigureAwait(false);
				await this.ApplyTrustSharingPreferenceAsync().ConfigureAwait(false);

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
				effectiveRiskScore = this.latestReportEffectiveRiskScore;
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
			await this.JoinableTaskFactory.SwitchToMainThreadAsync(this.DisposalToken);

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
		/// <returns>A task that completes when policy-triggered rescan processing finishes.</returns>
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
		/// <param name="preferredPolicyType">Optional policy scope to preselect when the editor opens.</param>
		/// <returns>A task that completes when the editor has been opened and initialized.</returns>
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

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);
			var projectPath  = Services.SolutionExplorerProjectDiscoveryService.GetSelectedProjectPath();
			var dialog = new ToolWindows.ManageAssemblyTrustsDialog(solutionPath ?? string.Empty, projectPath ?? string.Empty)
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
		/// Opens the Manage Package Trusts dialog for managing trusted packages by directory hash.
		/// </summary>
		/// <returns>A task that completes when the dialog is closed.</returns>
		internal async Task ShowManagePackageTrustsAsync()
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);

			var projectPath  = Services.SolutionExplorerProjectDiscoveryService.GetSelectedProjectPath();

			var dialog = new ToolWindows.ManagePackageTrustsDialog(solutionPath ?? string.Empty, projectPath ?? string.Empty)
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

			await this.UiFeedbackService.WriteLineAsync("Manage Package Trusts dialog closed.", CancellationToken.None);
		}

		/// <summary>
		/// Opens the Manage Signer Trusts dialog for managing trusted certificate signers.
		/// </summary>
		/// <returns>A task that completes when the dialog is closed.</returns>
		internal async Task ShowManageSignerTrustsAsync()
		{
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this);
			var projectPath  = Services.SolutionExplorerProjectDiscoveryService.GetSelectedProjectPath();
			var dialog = new ToolWindows.ManageSignerTrustsDialog(solutionPath ?? string.Empty, projectPath ?? string.Empty)
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

				var options = await this.GetOptionsSnapshotAsync(this.DisposalToken).ConfigureAwait(false);
				var solutionPath = e.Target.TargetPath;
				var solutionDir = !string.IsNullOrWhiteSpace(solutionPath) ? Path.GetDirectoryName(solutionPath) : null;
				var isUnseen = false;

				if (!string.IsNullOrWhiteSpace(solutionDir))
				{
					var trustPath = Path.Combine(solutionDir!, ".msbuildguard", "trust.json");
					var baselinePath = Path.Combine(solutionDir!, ".msbuildguard", "baseline.json");

					if (!File.Exists(trustPath) && !File.Exists(baselinePath))
					{
						isUnseen = true;
					}
				}

				if (e.Target.TargetKind == Core.TargetKind.Solution && isUnseen && !this.promptedSolutions.Contains(solutionPath) && options.EnableBaselineOnboarding)
				{
					this.promptedSolutions.Add(solutionPath);
					await this.RunOnboardingWorkflowAsync(solutionPath, e);

					return;
				}

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
					var solutionReport = await new Services.VisualStudioScannerService(this).ScanSolutionAsync(discoveredSolutionPath!, DisposalToken);
					this.UpdateLatestScanReport(solutionReport);
					reviewWindow.LoadReport(discoveredSolutionPath!, solutionReport);
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

		/// <summary>
		/// Applies the global trust-sharing option to managed <c>.gitignore</c> entries for the open solution.
		/// </summary>
		/// <returns>A task that completes when trust-sharing synchronization has finished.</returns>
		internal async Task ApplyTrustSharingPreferenceAsync()
		{
			await this.JoinableTaskFactory.SwitchToMainThreadAsync(this.DisposalToken);

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this).ConfigureAwait(false);

			if (string.IsNullOrWhiteSpace(solutionPath) || !File.Exists(solutionPath))
			{
				return;
			}

			var options = await this.GetOptionsSnapshotAsync(this.DisposalToken).ConfigureAwait(false);
			var changed = await Task.Run(() =>
				Services.GitIgnoreTrustSharingService.ApplyForSolution(solutionPath!, options.AllowSharingTrustsInRepositories),
				this.DisposalToken).ConfigureAwait(false);

			if (changed > 0)
			{
				await this.UiFeedbackService.WriteLineAsync($"Updated {changed} .gitignore file(s) for trust sharing preference.", CancellationToken.None);
			}
		}

		/// <summary>
		/// Resolves the display target path for review operations using explicit target path first and report path as fallback.
		/// </summary>
		/// <param name="targetPath">Explicit target path provided by the caller.</param>
		/// <param name="report">Scan report that may provide a target path fallback.</param>
		/// <returns>The resolved target path or <c>Unknown target</c> when no path is available.</returns>
		private static string ResolveTargetPath(string? targetPath, Core.ScanReport report)
		{
			if (!string.IsNullOrWhiteSpace(targetPath))
			{
				return targetPath!;
			}

			if (!string.IsNullOrWhiteSpace(report.Target.TargetPath))
			{
				return report.Target.TargetPath;
			}

			return "Unknown target";
		}

		/// <summary>
		/// Asynchronously recalculates the effective risk score and green state in the background.
		/// </summary>
		/// <returns>A task representing the asynchronous recalculation.</returns>
		internal async Task RecalculateEffectiveRiskAsync()
		{
			var report = this.latestScanReport;

			if (report == null)
			{
				this.isLatestReportGreen = false;
				this.latestReportEffectiveRiskScore = 0;

				return;
			}

			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			var solutionPath = Services.SolutionDiscoveryService.GetOpenSolutionPath();

			// Switch to a background thread to prevent blocking UI responsiveness!
			await TaskScheduler.Default;

			var buildBlockViewModel = new ToolWindows.BuildBlockDialogViewModel(report, solutionPath);

			this.isLatestReportGreen = string.Equals(buildBlockViewModel.RecommendedAction, Core.RecommendedAction.Allow.ToString(), StringComparison.OrdinalIgnoreCase);
			this.latestReportEffectiveRiskScore = buildBlockViewModel.RiskScore;

			// Switch back to the UI thread to update controls and trigger VS menu updates
			await JoinableTaskFactory.SwitchToMainThreadAsync(DisposalToken);

			await this.RefreshStatusBarShieldAsync().ConfigureAwait(false);

			if (await this.GetServiceAsync(typeof(SVsUIShell)) is IVsUIShell uiShell)
			{
				uiShell.UpdateCommandUI(1);
			}
		}

		/// <summary>
		/// Executes the onboarding trusted baseline setup workflow.
		/// </summary>
		/// <param name="solutionPath">The path of the open solution.</param>
		/// <param name="report">The scan report.</param>
		/// <returns>A task that completes when the workflow finishes.</returns>
		private async Task RunOnboardingWorkflowAsync(string solutionPath, Core.ScanReport report)
		{
			await this.JoinableTaskFactory.SwitchToMainThreadAsync(this.DisposalToken);

			this.promptedSolutions.Add(solutionPath);

			var result = Microsoft.VisualStudio.Shell.VsShellUtilities.ShowMessageBox(
				this,
				"This solution has not been scanned before by MSBuild Guard. Would you like to quickly set up a trusted baseline of its packages and assemblies?",
				"MSBuild Guard - Trusted Baseline Onboarding",
				OLEMSGICON.OLEMSGICON_QUERY,
				OLEMSGBUTTON.OLEMSGBUTTON_YESNO,
				OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);

			if (result != (int)Microsoft.VisualStudio.VSConstants.MessageBoxResult.IDYES)
			{
				return;
			}

			await this.UiFeedbackService.WriteLineAsync("Generating trusted baseline suggestions...", CancellationToken.None);

			var onboardingService = new Core.Baseline.BaselineOnboardingService();
			var suggestions = await onboardingService.GenerateSuggestionsAsync(report, this.DisposalToken).ConfigureAwait(true);

			await this.JoinableTaskFactory.SwitchToMainThreadAsync(this.DisposalToken);

			var vm = new ToolWindows.BaselineOnboardingViewModel(suggestions);
			var dialog = new ToolWindows.BaselineOnboardingDialog(vm)
			{
				Owner = System.Windows.Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner
			};

			var dialogResult = dialog.ShowDialog();
			var trustService = new Core.Trust.TrustStoreService();
			var solutionTrustPath = trustService.GetSolutionTrustPath(solutionPath);

			if (dialogResult == true)
			{
				var selectedSuggestions = vm.Suggestions.Where(s => s.IsSelected).ToList();
				var userSid = System.Security.Principal.WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				await this.UiFeedbackService.WriteLineAsync($"Applying {selectedSuggestions.Count} selected trusts...", CancellationToken.None);
				ApplySelectedSuggestions(solutionPath, vm.SelectedTrustScope, report, selectedSuggestions, userSid);

				if (vm.CreateBaselineForRemaining)
				{
					await this.UiFeedbackService.WriteLineAsync("Creating baseline for remaining findings...", CancellationToken.None);
					CreateRemainingFindingsBaseline(solutionPath, report);
				}

				if (vm.DoNotScanAgain)
				{
					WriteDisableScanMarker(solutionPath);
				}

				await this.UiFeedbackService.WriteLineAsync("Trusted baseline onboarding complete.", CancellationToken.None);

				Microsoft.VisualStudio.Shell.VsShellUtilities.ShowMessageBox(
					this,
					"Trusted baseline onboarding complete. The solution is now configured with the chosen trusts and baseline.",
					"MSBuild Guard",
					OLEMSGICON.OLEMSGICON_INFO,
					OLEMSGBUTTON.OLEMSGBUTTON_OK,
					OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);

				await this.RescanSolutionSecurityReviewAsync();
			}
			else
			{
				if (vm.DontShowAgain)
				{
					WriteEmptyTrustStore(solutionTrustPath);
				}

				if (vm.DoNotScanAgain)
				{
					WriteDisableScanMarker(solutionPath);
				}
			}
		}

		/// <summary>
		/// Resolves the absolute project path for a finding.
		/// </summary>
		/// <param name="solutionPath">The path to the solution file.</param>
		/// <param name="finding">The scan finding.</param>
		/// <returns>The resolved project path, or null if it cannot be resolved.</returns>
		private static string? ResolveProjectPath(string solutionPath, Core.Finding finding)
		{
			if (!string.IsNullOrWhiteSpace(finding.IntroducedViaProject))
			{
				return Path.IsPathRooted(finding.IntroducedViaProject)
					? Path.GetFullPath(finding.IntroducedViaProject)
					: Path.GetFullPath(Path.Combine(Path.GetDirectoryName(solutionPath) ?? string.Empty, finding.IntroducedViaProject));
			}

			if (finding.FilePath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
				finding.FilePath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
				finding.FilePath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
			{
				return Path.GetFullPath(finding.FilePath);
			}

			return null;
		}

		/// <summary>
		/// Applies selected trust suggestions to the chosen trust store level.
		/// </summary>
		/// <param name="solutionPath">The path to the solution file.</param>
		/// <param name="selectedScope">The chosen trust scope level (User, Solution, or Project).</param>
		/// <param name="report">The scan report context.</param>
		/// <param name="selectedSuggestions">The list of suggestions chosen by the user.</param>
		/// <param name="userSid">The user's SID.</param>
		private static void ApplySelectedSuggestions(
			string solutionPath,
			string selectedScope,
			Core.ScanReport report,
			List<ToolWindows.TrustSuggestionItemViewModel> selectedSuggestions,
			string userSid)
		{
			var trustService = new Core.Trust.TrustStoreService();

			foreach (var item in selectedSuggestions)
			{
				var suggestion = item.Suggestion;
				var targetPaths = new List<string>();

				if (selectedScope.Equals("User", StringComparison.OrdinalIgnoreCase))
				{
					targetPaths.Add(trustService.GetDefaultUserTrustPath());
				}
				else if (selectedScope.Equals("Solution", StringComparison.OrdinalIgnoreCase))
				{
					targetPaths.Add(trustService.GetSolutionTrustPath(solutionPath));
				}
				else if (selectedScope.Equals("Project", StringComparison.OrdinalIgnoreCase))
				{
					var projectPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

					if (suggestion.Scope == Core.Baseline.TrustSuggestionScope.Package)
					{
						var packageId = suggestion.Metadata.TryGetValue("PackageId", out var pid) ? pid : string.Empty;

						if (!string.IsNullOrEmpty(packageId))
						{
							foreach (var finding in report.Findings)
							{
								if (string.Equals(finding.PackageId, packageId, StringComparison.OrdinalIgnoreCase))
								{
									var proj = ResolveProjectPath(solutionPath, finding);

									if (proj != null)
									{
										projectPaths.Add(proj);
									}
								}
							}
						}
					}
					else if (suggestion.Scope == Core.Baseline.TrustSuggestionScope.Assembly)
					{
						var assemblyName = suggestion.Metadata.TryGetValue("AssemblyName", out var aname) ? aname : string.Empty;

						if (!string.IsNullOrEmpty(assemblyName))
						{
							foreach (var finding in report.Findings)
							{
								if (finding.FilePath.IndexOf(assemblyName, StringComparison.OrdinalIgnoreCase) >= 0)
								{
									var proj = ResolveProjectPath(solutionPath, finding);

									if (proj != null)
									{
										projectPaths.Add(proj);
									}
								}
							}
						}
					}
					else if (suggestion.Scope == Core.Baseline.TrustSuggestionScope.Signer)
					{
						var thumbprint = suggestion.Metadata.TryGetValue("SignerThumbprint", out var thumb) ? thumb : string.Empty;

						if (!string.IsNullOrEmpty(thumbprint))
						{
							foreach (var finding in report.Findings)
							{
								if (string.Equals(finding.PackageSignatureState, thumbprint, StringComparison.OrdinalIgnoreCase))
								{
									var proj = ResolveProjectPath(solutionPath, finding);

									if (proj != null)
									{
										projectPaths.Add(proj);
									}
								}
							}
						}
					}

					if (projectPaths.Count == 0)
					{
						foreach (var file in report.FilesScanned)
						{
							if (file.FileKind == Core.MsBuildFileKind.Project ||
								file.Path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
								file.Path.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
								file.Path.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
							{
								projectPaths.Add(file.Path);
							}
						}
					}

					foreach (var proj in projectPaths)
					{
						targetPaths.Add(trustService.GetProjectTrustPath(proj));
					}
				}
				else
				{
					targetPaths.Add(trustService.GetSolutionTrustPath(solutionPath));
				}

				foreach (var targetPath in targetPaths)
				{
					if (suggestion.Scope == Core.Baseline.TrustSuggestionScope.Signer)
					{
						trustService.AddSignerTrust(
							targetPath,
							suggestion.Metadata.TryGetValue("SignerThumbprint", out var thumb) ? thumb : string.Empty,
							suggestion.Metadata.TryGetValue("SignerSubject", out var subj) ? subj : string.Empty,
							suggestion.DisplayName,
							suggestion.Metadata.TryGetValue("SignerIssuer", out var iss) ? iss : string.Empty,
							suggestion.Metadata.TryGetValue("SignerSerialNumber", out var ser) ? ser : string.Empty,
							suggestion.RecommendationReason,
							userSid);
					}
					else if (suggestion.Scope == Core.Baseline.TrustSuggestionScope.Package)
					{
						trustService.AddPackageTrust(
							targetPath,
							suggestion.Metadata.TryGetValue("PackageId", out var pid) ? pid : string.Empty,
							suggestion.Metadata.TryGetValue("PackageVersion", out var pver) ? pver : string.Empty,
							suggestion.Metadata.TryGetValue("PackageHash", out var phash) ? phash : string.Empty,
							suggestion.RecommendationReason,
							userSid);
					}
					else if (suggestion.Scope == Core.Baseline.TrustSuggestionScope.Assembly)
					{
						trustService.AddAssemblyTrust(
							targetPath,
							suggestion.Metadata.TryGetValue("AssemblyName", out var aname) ? aname : string.Empty,
							suggestion.Metadata.TryGetValue("AssemblyVersion", out var aver) ? aver : string.Empty,
							suggestion.RecommendationReason,
							userSid,
							suggestion.Metadata.TryGetValue("AssemblySigner", out var asig) ? asig : string.Empty,
							suggestion.Metadata.TryGetValue("AssemblyIssuer", out var aiss) ? aiss : string.Empty,
							suggestion.Metadata.TryGetValue("AssemblySubject", out var asubj) ? asubj : string.Empty);
					}
				}
			}
		}

		/// <summary>
		/// Creates and saves a baseline document for any findings not currently approved in the trust store.
		/// </summary>
		/// <param name="solutionPath">The solution file path.</param>
		/// <param name="report">The scan report.</param>
		private static void CreateRemainingFindingsBaseline(string solutionPath, Core.ScanReport report)
		{
			var trustService = new Core.Trust.TrustStoreService();
			var currentTrustStore = trustService.LoadMergedTrustStore(trustService.GetDefaultUserTrustPath(), solutionPath, null);
			var filteredFindings = report.Findings.Where(f => !IsFindingTrusted(f, currentTrustStore)).ToList();
			var filteredReport = new Core.ScanReport
			{
				ScannerVersion = report.ScannerVersion,
				ReportVersion = report.ReportVersion,
				Target = report.Target,
				PolicyProfile = report.PolicyProfile
			};

			foreach (var file in report.FilesScanned)
			{
				filteredReport.FilesScanned.Add(file);
			}

			foreach (var finding in filteredFindings)
			{
				filteredReport.Findings.Add(finding);
			}

			var baselineService = new Core.Baseline.BaselineService();
			var solutionDir = Path.GetDirectoryName(solutionPath);

			if (!string.IsNullOrWhiteSpace(solutionDir))
			{
				var baselinePath = Path.Combine(solutionDir!, ".msbuildguard", "baseline.json");
				var baseline = baselineService.CreateFromReport(filteredReport, "visualstudio", Environment.UserName);

				baselineService.Save(baselinePath, baseline);
			}
		}

		private static bool IsFindingTrusted(Core.Finding f, Core.Trust.TrustStoreDocument currentTrustStore)
		{
			if (f.IsTrusted)
			{
				return true;
			}

			var trustService = new Core.Trust.TrustStoreService();

			if (trustService.IsFingerprintApproved(currentTrustStore, f.Fingerprint))
			{
				return true;
			}

			if (!string.IsNullOrWhiteSpace(f.PackageId) && !string.IsNullOrWhiteSpace(f.PackageVersion))
			{
				if (trustService.IsFindingApprovedByAssembly(currentTrustStore, f.PackageId, f.PackageVersion))
				{
					return true;
				}

				if (f.FilePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || f.FilePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
				{
					var assemblyPath = Core.Trust.AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(f.PackageId, f.PackageVersion);
					var sig = new Core.Trust.AssemblySignatureService().ReadSignature(assemblyPath);

					if (sig != null && sig.HasEmbeddedSignature && sig.IsSignatureValid &&
						trustService.IsSignerTrusted(currentTrustStore, sig.Thumbprint, sig.Subject, sig.Issuer, sig.SerialNumber))
					{
						return true;
					}
				}
			}

			return false;
		}

		/// <summary>
		/// Writes a marker file to disable future scanning of the solution.
		/// </summary>
		/// <param name="solutionPath">The solution file path.</param>
		private static void WriteDisableScanMarker(string solutionPath)
		{
			var solutionDir = Path.GetDirectoryName(solutionPath);

			if (!string.IsNullOrWhiteSpace(solutionDir))
			{
				var noscanPath = Path.Combine(solutionDir!, ".msbuildguard", "noscan");
				var directory = Path.GetDirectoryName(noscanPath);

				if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
				{
					Directory.CreateDirectory(directory);
				}

				File.WriteAllText(noscanPath, "Scanning disabled.");
			}
		}

		/// <summary>
		/// Initializes an empty solution-level trust store so onboarding is not prompted again.
		/// </summary>
		/// <param name="solutionTrustPath">The solution trust store file path.</param>
		private static void WriteEmptyTrustStore(string solutionTrustPath)
		{
			var trustService = new Core.Trust.TrustStoreService();
			var directory = Path.GetDirectoryName(solutionTrustPath);

			if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
			{
				Directory.CreateDirectory(directory);
			}

			trustService.Save(solutionTrustPath, new Core.Trust.TrustStoreDocument());
		}

		/// <summary>
		/// Selects the preferred scan report by keeping the most recently completed report.
		/// </summary>
		/// <param name="current">Current scan report.</param>
		/// <param name="candidate">Candidate scan report.</param>
		/// <returns>The preferred report based on completion time.</returns>
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
