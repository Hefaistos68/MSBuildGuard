using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Events;
using MSBuildGuard.Core;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Monitors Visual Studio solution lifecycle events and triggers early scans.
	/// </summary>
	internal sealed class SolutionMonitorService : IDisposable
	{
		private readonly MSBuildGuardPackage package;
		private readonly VisualStudioScannerService scannerService;
		private readonly SemaphoreSlim scanGate;
		private readonly object syncRoot;

		private bool isStarted;
		private string? lastScannedSolutionPath;

		/// <summary>
		/// Initializes a new instance of the <see cref="SolutionMonitorService"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		public SolutionMonitorService(AsyncPackage package)
		{
			this.package       = (MSBuildGuardPackage)package;
			this.scannerService = new VisualStudioScannerService(this.package);
			this.scanGate      = new SemaphoreSlim(1, 1);
			this.syncRoot      = new object();
		}

		/// <summary>
		/// Occurs after a solution scan completes.
		/// </summary>
		public event EventHandler<ScanReport>? ScanCompleted;

		/// <summary>
		/// Starts monitoring solution events and performs an initial scan if a solution is already open.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A task that completes when startup work is scheduled.</returns>
		public async Task StartAsync(CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			if (this.isStarted)
			{
				return;
			}

			SolutionEvents.OnAfterOpenSolution += this.OnAfterOpenSolution;
			SolutionEvents.OnAfterCloseSolution += this.OnAfterCloseSolution;
			SolutionEvents.OnBeforeOpenProject += this.OnBeforeOpenProject;
			this.isStarted = true;

			await this.package.UiFeedbackService.WriteLineAsync("Solution monitor started.", CancellationToken.None);
			_ = this.QueueScanAsync(null, cancellationToken);
		}

		/// <summary>
		/// Releases monitoring subscriptions and resources.
		/// </summary>
		public void Dispose()
		{
			if (this.isStarted)
			{
				SolutionEvents.OnAfterOpenSolution -= this.OnAfterOpenSolution;
				SolutionEvents.OnAfterCloseSolution -= this.OnAfterCloseSolution;
				SolutionEvents.OnBeforeOpenProject -= this.OnBeforeOpenProject;
				this.isStarted = false;
			}

			this.scanGate.Dispose();
		}

		/// <summary>
		/// Handles the after-open-solution event by queueing a new scan.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Solution open event arguments.</param>
		private void OnAfterOpenSolution(object? sender, OpenSolutionEventArgs e)
		{
			_ = this.package.UiFeedbackService.WriteLineAsync("Solution opened.", CancellationToken.None);
			_ = this.QueueScanAsync(null, this.package.DisposalToken);
		}

		/// <summary>
		/// Handles the before-open-project event by queuing a project-open scan.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Project-open event arguments.</param>
		private void OnBeforeOpenProject(object? sender, BeforeOpenProjectEventArgs e)
		{
			_ = this.package.UiFeedbackService.WriteLineAsync($"Project opening: {e.Filename}", CancellationToken.None);
			_ = this.package.UiFeedbackService.WriteLineAsync("[Flow] OnBeforeOpenProject -> QueueScanAsync target='<open-solution>', forceRescan=false", CancellationToken.None);
			_ = this.QueueScanAsync(null, this.package.DisposalToken, false);
		}

		/// <summary>
		/// Handles the after-close-solution event by clearing the cached scan path and notifying the package.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Event arguments.</param>
		private void OnAfterCloseSolution(object? sender, EventArgs e)
		{
			lock (this.syncRoot)
			{
				this.lastScannedSolutionPath = null;
			}

			_ = this.package.OnSolutionUnloadedAsync();
		}

		/// <summary>
		/// Acquires the scan gate, resolves the target path, runs the scanner, and raises <see cref="ScanCompleted"/>.
		/// </summary>
		/// <param name="targetPath">Optional explicit target path; the open solution path is used when <c>null</c>.</param>
		/// <param name="cancellationToken">Cancellation token for the scan operation.</param>
		/// <param name="forceRescan">When <c>true</c>, bypasses the duplicate-path guard.</param>
		/// <returns>A task that completes when the scan and notification are done.</returns>
		private async Task QueueScanAsync(string? targetPath, CancellationToken cancellationToken, bool forceRescan = false)
		{
			await this.package.UiFeedbackService.WriteLineAsync($"[Flow] QueueScanAsync entered with target='{targetPath ?? string.Empty}', forceRescan={forceRescan}", CancellationToken.None);

			bool acquired = false;

			try
			{
				if (string.IsNullOrWhiteSpace(targetPath))
				{
					targetPath = await SolutionDiscoveryService.GetOpenSolutionPathAsync(this.package).ConfigureAwait(false);
					await this.package.UiFeedbackService.WriteLineAsync($"[Flow] QueueScanAsync resolved open solution target='{targetPath ?? string.Empty}'", CancellationToken.None);
				}

				if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
				{
					await this.package.UiFeedbackService.WriteLineAsync("No solution or project path was available to scan.", CancellationToken.None);

					return;
				}

				var scanPath = targetPath!;

				lock (this.syncRoot)
				{
					if (!forceRescan && string.Equals(scanPath, this.lastScannedSolutionPath, StringComparison.OrdinalIgnoreCase))
					{
						_ = this.package.UiFeedbackService.WriteLineAsync($"[Flow] QueueScanAsync skipped duplicate target='{scanPath}'", CancellationToken.None);

						return;
					}

					this.lastScannedSolutionPath = scanPath;
				}

				await this.scanGate.WaitAsync(cancellationToken).ConfigureAwait(false);
				acquired = true;

				await this.package.UiFeedbackService.WriteLineAsync($"Queued scan: {scanPath}", CancellationToken.None);

				var report = await this.scannerService.ScanSolutionAsync(scanPath, cancellationToken).ConfigureAwait(false);

				await this.package.UiFeedbackService.WriteLineAsync($"[Flow] QueueScanAsync completed scan target='{scanPath}', findings={report.Findings.Count}, kind={report.Target.TargetKind}", CancellationToken.None);

				this.ScanCompleted?.Invoke(this, report);
				await this.package.UiFeedbackService.WriteLineAsync("[Flow] QueueScanAsync raised ScanCompleted event", CancellationToken.None);
			}
			catch (OperationCanceledException)
			{
				await this.package.UiFeedbackService.WriteLineAsync("Queued scan canceled.", CancellationToken.None);
			}
			catch (Exception ex)
			{
				await this.package.UiFeedbackService.WriteLineAsync($"Queued scan failed: {ex.Message}", CancellationToken.None);
			}
			finally
			{
				if (acquired)
				{
					this.scanGate.Release();
				}
			}
		}
	}
}
