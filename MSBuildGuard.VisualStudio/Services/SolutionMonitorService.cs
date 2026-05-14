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

		private void OnAfterOpenSolution(object? sender, OpenSolutionEventArgs e)
		{
			_ = this.package.UiFeedbackService.WriteLineAsync("Solution opened.", CancellationToken.None);
			_ = this.QueueScanAsync(null, this.package.DisposalToken);
		}

		private void OnBeforeOpenProject(object? sender, BeforeOpenProjectEventArgs e)
		{
			_ = this.package.UiFeedbackService.WriteLineAsync($"Project opening: {e.Filename}", CancellationToken.None);
			_ = this.QueueScanAsync(e.Filename, this.package.DisposalToken);
		}

		private void OnAfterCloseSolution(object? sender, EventArgs e)
		{
			lock (this.syncRoot)
			{
				this.lastScannedSolutionPath = null;
			}

			_ = this.package.OnSolutionUnloadedAsync();
		}

		private async Task QueueScanAsync(string? targetPath, CancellationToken cancellationToken)
		{
			await this.scanGate.WaitAsync(cancellationToken).ConfigureAwait(false);

			try
			{
				if (string.IsNullOrWhiteSpace(targetPath))
				{
					targetPath = await SolutionDiscoveryService.GetOpenSolutionPathAsync(this.package).ConfigureAwait(false);
				}

				if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
				{
					await this.package.UiFeedbackService.WriteLineAsync("No solution or project path was available to scan.", CancellationToken.None);
					return;
				}

				var scanPath = targetPath!;

				lock (this.syncRoot)
				{
					if (string.Equals(scanPath, this.lastScannedSolutionPath, StringComparison.OrdinalIgnoreCase))
					{
						return;
					}

					this.lastScannedSolutionPath = scanPath;
				}

				await this.package.UiFeedbackService.WriteLineAsync($"Queued scan: {scanPath}", CancellationToken.None);
				var report = await this.scannerService.ScanSolutionAsync(scanPath, cancellationToken).ConfigureAwait(false);

				this.ScanCompleted?.Invoke(this, report);
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
				this.scanGate.Release();
			}
		}
	}
}
