using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.ComponentModelHost;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Events;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Monitors NuGet restore completion and raises rescans when package state changes.
	/// </summary>
	internal sealed class NuGetRestoreMonitorService : IDisposable
	{
		private const string NuGetProjectUpdateEventsTypeName = "NuGet.VisualStudio.IVsNuGetProjectUpdateEvents, NuGet.VisualStudio";
		private const string SolutionRestoreFinishedEventName = "SolutionRestoreFinished";
		private const string ProjectUpdateFinishedEventName = "ProjectUpdateFinished";
		private const string SolutionRestoreEventHandlerTypeName = "NuGet.VisualStudio.SolutionRestoreEventHandler, NuGet.VisualStudio";
		private const string ProjectUpdateEventHandlerTypeName = "NuGet.VisualStudio.ProjectUpdateEventHandler, NuGet.VisualStudio";

		private readonly MSBuildGuardPackage package;
		private readonly VisualStudioScannerService scannerService;
		private readonly SemaphoreSlim scanGate;

		private object? nuGetProjectUpdateEvents;
		private Delegate? solutionRestoreFinishedHandler;
		private Delegate? projectUpdateFinishedHandler;
		private bool isStarted;
		private bool handlersBound;
		private bool retryBindingOnSolutionOpenSubscribed;

		/// <summary>
		/// Initializes a new instance of the <see cref="NuGetRestoreMonitorService"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		public NuGetRestoreMonitorService(AsyncPackage package)
		{
			this.package = (MSBuildGuardPackage)package;
			this.scannerService = new VisualStudioScannerService(this.package);
			this.scanGate = new SemaphoreSlim(1, 1);
		}

		/// <summary>
		/// Starts monitoring NuGet restore completion events.
		/// </summary>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A task that completes when monitoring has been initialized.</returns>
		public async Task StartAsync(CancellationToken cancellationToken)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			if (this.isStarted)
			{
				return;
			}

			this.isStarted = true;
			this.retryBindingOnSolutionOpenSubscribed = true;
			SolutionEvents.OnAfterOpenSolution += this.OnAfterOpenSolution;

			var componentModel = await this.package.GetComponentModelAsync(cancellationToken).ConfigureAwait(false);

			if (this.TryBindRestoreHandlers(componentModel))
			{
				await this.package.UiFeedbackService.WriteLineAsync("NuGet restore monitor started.", CancellationToken.None);
				this.UnsubscribeRetryBindingOnSolutionOpen();
				return;
			}

			await this.package.UiFeedbackService.WriteLineAsync("NuGet restore monitor deferred: handlers will be bound when a solution is opened.", CancellationToken.None);

			if (SolutionDiscoveryService.HasOpenSolution())
			{
				this.OnAfterOpenSolution(this, new OpenSolutionEventArgs(false));
			}
		}

		/// <summary>
		/// Releases restore subscriptions and resources.
		/// </summary>
		public void Dispose()
		{
			if (this.handlersBound && this.nuGetProjectUpdateEvents != null)
			{
				if (this.solutionRestoreFinishedHandler != null)
				{
					this.RemoveHandler(SolutionRestoreFinishedEventName, this.solutionRestoreFinishedHandler);
				}

				if (this.projectUpdateFinishedHandler != null)
				{
					this.RemoveHandler(ProjectUpdateFinishedEventName, this.projectUpdateFinishedHandler);
				}

				this.nuGetProjectUpdateEvents = null;
				this.solutionRestoreFinishedHandler = null;
				this.projectUpdateFinishedHandler = null;
			}

			this.handlersBound = false;
			this.UnsubscribeRetryBindingOnSolutionOpen();

			this.isStarted = false;
			this.scanGate.Dispose();
		}

		/// <summary>
		/// Handles solution-open events and retries NuGet restore handler binding.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Solution open event arguments.</param>
		private void OnAfterOpenSolution(object? sender, OpenSolutionEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(this.package.DisposalToken);

				if (this.handlersBound)
				{
					this.UnsubscribeRetryBindingOnSolutionOpen();
					return;
				}

				var componentModel = await this.package.GetComponentModelAsync(this.package.DisposalToken).ConfigureAwait(false);

				if (!this.TryBindRestoreHandlers(componentModel))
				{
					await this.package.UiFeedbackService.WriteLineAsync("NuGet restore monitor could not bind restore event handlers after solution open.", CancellationToken.None);
					return;
				}

				await this.package.UiFeedbackService.WriteLineAsync("NuGet restore monitor started.", CancellationToken.None);
				this.UnsubscribeRetryBindingOnSolutionOpen();
			}).FileAndForget(nameof(NuGetRestoreMonitorService));
		}

		/// <summary>
		/// Handles NuGet solution-level restore completion and queues a rescan.
		/// </summary>
		/// <param name="projects">Projects included in the restore event.</param>
		private void OnSolutionRestoreFinished(IReadOnlyList<string> projects)
		{
			_ = this.package.UiFeedbackService.WriteLineAsync("NuGet solution restore completed.", CancellationToken.None);
			_ = this.QueueRescanAsync(null, this.package.DisposalToken);
		}

		/// <summary>
		/// Handles NuGet project-level restore completion and queues a rescan.
		/// </summary>
		/// <param name="projectUniqueName">The project unique name associated with the event.</param>
		/// <param name="updatedFiles">Files updated by restore.</param>
		private void OnProjectUpdateFinished(string projectUniqueName, IReadOnlyList<string> updatedFiles)
		{
			_ = this.package.UiFeedbackService.WriteLineAsync($"NuGet project restore completed: {projectUniqueName}", CancellationToken.None);
			_ = this.QueueRescanAsync(projectUniqueName, this.package.DisposalToken);
		}

		/// <summary>
		/// Attempts to resolve the NuGet project update events service from the component model.
		/// </summary>
		/// <param name="componentModel">The Visual Studio component model.</param>
		/// <returns>The NuGet update events service instance when available; otherwise <c>null</c>.</returns>
		private static object? TryGetNuGetProjectUpdateEvents(IComponentModel? componentModel)
		{
			if (componentModel == null)
			{
				return null;
			}

			var serviceType = Type.GetType(NuGetProjectUpdateEventsTypeName, false);

			if (serviceType == null)
			{
				return null;
			}

			var getServiceMethod = typeof(IComponentModel).GetMethod("GetService");

			if (getServiceMethod == null)
			{
				return null;
			}

			var genericMethod = getServiceMethod.MakeGenericMethod(serviceType);

			return genericMethod.Invoke(componentModel, null);
		}

		/// <summary>
		/// Creates a delegate instance for the specified handler method name.
		/// </summary>
		/// <param name="delegateTypeName">Assembly-qualified delegate type name.</param>
		/// <param name="methodName">Private instance method name to bind.</param>
		/// <returns>The created delegate when binding succeeds; otherwise <c>null</c>.</returns>
		private Delegate? CreateHandler(string delegateTypeName, string methodName)
		{
			var delegateType = Type.GetType(delegateTypeName, false);

			if (delegateType == null)
			{
				return null;
			}

			var method = typeof(NuGetRestoreMonitorService).GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic);

			if (method == null)
			{
				return null;
			}

			try
			{
				return Delegate.CreateDelegate(delegateType, this, method, false);
			}
			catch (ArgumentException)
			{
				return null;
			}
		}

		/// <summary>
		/// Subscribes a handler delegate to a NuGet restore event by name.
		/// </summary>
		/// <param name="eventName">The NuGet event name.</param>
		/// <param name="handler">The delegate handler to subscribe.</param>
		private void AddHandler(string eventName, Delegate handler)
		{
			var eventInfo = this.nuGetProjectUpdateEvents?.GetType().GetEvent(eventName);

			eventInfo?.AddEventHandler(this.nuGetProjectUpdateEvents, handler);
		}

		/// <summary>
		/// Unsubscribes a handler delegate from a NuGet restore event by name.
		/// </summary>
		/// <param name="eventName">The NuGet event name.</param>
		/// <param name="handler">The delegate handler to unsubscribe.</param>
		private void RemoveHandler(string eventName, Delegate handler)
		{
			var eventInfo = this.nuGetProjectUpdateEvents?.GetType().GetEvent(eventName);

			eventInfo?.RemoveEventHandler(this.nuGetProjectUpdateEvents, handler);
		}

		/// <summary>
		/// Attempts to bind NuGet restore event handlers using the current component model.
		/// </summary>
		/// <param name="componentModel">The Visual Studio component model.</param>
		/// <returns><c>true</c> when handlers are bound; otherwise <c>false</c>.</returns>
		private bool TryBindRestoreHandlers(IComponentModel? componentModel)
		{
			this.nuGetProjectUpdateEvents = TryGetNuGetProjectUpdateEvents(componentModel);

			if (this.nuGetProjectUpdateEvents == null)
			{
				this.handlersBound = false;
				return false;
			}

			this.solutionRestoreFinishedHandler = this.CreateHandler(SolutionRestoreEventHandlerTypeName, nameof(this.OnSolutionRestoreFinished));
			this.projectUpdateFinishedHandler = this.CreateHandler(ProjectUpdateEventHandlerTypeName, nameof(this.OnProjectUpdateFinished));

			if (this.solutionRestoreFinishedHandler == null || this.projectUpdateFinishedHandler == null)
			{
				this.nuGetProjectUpdateEvents = null;
				this.solutionRestoreFinishedHandler = null;
				this.projectUpdateFinishedHandler = null;
				this.handlersBound = false;
				return false;
			}

			this.AddHandler(SolutionRestoreFinishedEventName, this.solutionRestoreFinishedHandler);
			this.AddHandler(ProjectUpdateFinishedEventName, this.projectUpdateFinishedHandler);
			this.handlersBound = true;

			return true;
		}

		/// <summary>
		/// Unsubscribes solution-open retry binding handler when no longer needed.
		/// </summary>
		private void UnsubscribeRetryBindingOnSolutionOpen()
		{
			if (!this.retryBindingOnSolutionOpenSubscribed)
			{
				return;
			}

			SolutionEvents.OnAfterOpenSolution -= this.OnAfterOpenSolution;
			this.retryBindingOnSolutionOpenSubscribed = false;
		}

		/// <summary>
		/// Queues a scan after restore completion for the provided target path or open solution.
		/// </summary>
		/// <param name="targetPath">Optional target path from the restore event.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A task that completes when queue processing finishes.</returns>
		private async Task QueueRescanAsync(string? targetPath, CancellationToken cancellationToken)
		{
			await this.scanGate.WaitAsync(cancellationToken).ConfigureAwait(false);

			try
			{
				if (string.IsNullOrWhiteSpace(targetPath))
				{
					targetPath = await SolutionDiscoveryService.GetOpenSolutionPathAsync(this.package).ConfigureAwait(false);
				}

				if (string.IsNullOrWhiteSpace(targetPath))
				{
					return;
				}

				var scanPath = targetPath!;
				var report = await this.scannerService.ScanSolutionAsync(scanPath, cancellationToken).ConfigureAwait(false);
				this.package.UpdateLatestScanReport(report);
			}
			catch (OperationCanceledException)
			{
			}
			finally
			{
				this.scanGate.Release();
			}
		}
	}
}
