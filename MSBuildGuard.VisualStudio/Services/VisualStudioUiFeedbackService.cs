using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Provides shared Visual Studio output window and status bar feedback.
	/// </summary>
	internal sealed class VisualStudioUiFeedbackService : IDisposable
	{
		private const string OutputPaneName = "MSBuild Guard";

		private readonly AsyncPackage package;
		private readonly SemaphoreSlim paneGate;

		private IVsOutputWindowPane? outputPane;
		private uint statusCookie;
		private bool statusProgressActive;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="VisualStudioUiFeedbackService"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		public VisualStudioUiFeedbackService(AsyncPackage package)
		{
			this.package   = package;
			this.paneGate  = new SemaphoreSlim(1, 1);
		}

		/// <summary>
		/// Writes a line to the MSBuild Guard output pane.
		/// </summary>
		/// <param name="message">The message to write.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		public async Task WriteLineAsync(string message, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(message))
			{
				return;
			}

			var redactedMessage = PathRedactionService.RedactMessage(message);

			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);
			await this.EnsureOutputPaneAsync(cancellationToken);

			this.outputPane?.OutputStringThreadSafe($"{redactedMessage}{Environment.NewLine}");
		}

		/// <summary>
		/// Starts status bar progress with a textual description.
		/// </summary>
		/// <param name="label">Status text.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		public async Task StartProgressAsync(string label, CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			var statusbar = await this.GetStatusBarAsync(cancellationToken);

			if (statusbar == null)
			{
				return;
			}

			statusbar.Progress(ref this.statusCookie, 1, label, 0, 100);
			this.statusProgressActive = true;
		}

		/// <summary>
		/// Updates the status bar progress value.
		/// </summary>
		/// <param name="label">Status text.</param>
		/// <param name="completed">Completed progress units.</param>
		/// <param name="total">Total progress units.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		public async Task ReportProgressAsync(string label, uint completed, uint total, CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			var statusbar = await this.GetStatusBarAsync(cancellationToken);

			if (statusbar == null)
			{
				return;
			}

			statusbar.Progress(ref this.statusCookie, 1, label, completed, total);
			this.statusProgressActive = true;
		}

		/// <summary>
		/// Completes status bar progress and clears the text.
		/// </summary>
		/// <param name="label">Completion text.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		public async Task CompleteProgressAsync(string label, CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			var statusbar = await this.GetStatusBarAsync(cancellationToken);

			if (statusbar == null)
			{
				return;
			}

			if (this.statusProgressActive)
			{
				statusbar.Progress(ref this.statusCookie, 0, label, 0, 100);
				this.statusProgressActive = false;
			}

			statusbar.SetText(label);
		}

		/// <summary>
		/// Releases the semaphore gate and marks this instance as disposed.
		/// </summary>
		public void Dispose()
		{
			if (this.disposed)
			{
				return;
			}

			this.disposed = true;
			this.paneGate.Dispose();
		}

		/// <summary>
		/// Lazily initializes the MSBuild Guard output pane, creating it if it does not yet exist.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task that completes when the pane is ready.</returns>
		private async Task EnsureOutputPaneAsync(CancellationToken cancellationToken)
		{
			if (this.outputPane != null)
			{
				return;
			}

			await this.paneGate.WaitAsync(cancellationToken).ConfigureAwait(false);

			try
			{
				if (this.outputPane != null)
				{
					return;
				}

				await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

				var outputWindow = await this.package.GetServiceAsync(typeof(SVsOutputWindow)) as IVsOutputWindow;

				if (outputWindow == null)
				{
					return;
				}

				var paneGuid = new Guid("c6e5d9f6-2d0a-4f60-a9b2-4d76cc5f5f7a");
				outputWindow.CreatePane(ref paneGuid, OutputPaneName, 1, 1);
				outputWindow.GetPane(ref paneGuid, out this.outputPane);

				this.outputPane?.Activate();
			}
			finally
			{
				this.paneGate.Release();
			}
		}

		/// <summary>
		/// Retrieves the Visual Studio status bar service.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>The <see cref="IVsStatusbar"/> service, or <c>null</c> when unavailable.</returns>
		private async Task<IVsStatusbar?> GetStatusBarAsync(CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			var statusbar = await this.package.GetServiceAsync(typeof(SVsStatusbar)) as IVsStatusbar;

			return statusbar;
		}
	}
}
