using System;
using System.ComponentModel.Design;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.Commands
{
	/// <summary>
	/// Implements the command that opens the Solution Security Review tool window.
	/// </summary>
	internal sealed class OpenSolutionSecurityReviewCommand
	{
		private readonly MSBuildGuardPackage package;
		private readonly VisualStudioScannerService scannerService;

		/// <summary>
		/// Initializes a new instance of the <see cref="OpenSolutionSecurityReviewCommand"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <param name="commandService">Menu command service.</param>
		private OpenSolutionSecurityReviewCommand(AsyncPackage package, OleMenuCommandService commandService)
		{
			this.package        = (MSBuildGuardPackage)package;
			this.scannerService = new VisualStudioScannerService(this.package);

			var menuCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.OpenSolutionReviewCommandId);
			var menuItem      = new OleMenuCommand(this.Execute, menuCommandId);

			menuItem.BeforeQueryStatus += this.OnBeforeQueryStatus;
			commandService.AddCommand(menuItem);

			var contextCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.OpenSolutionReviewContextCommandId);
			var contextMenuItem  = new OleMenuCommand(this.Execute, contextCommandId);

			contextMenuItem.BeforeQueryStatus += this.OnBeforeQueryStatus;
			commandService.AddCommand(contextMenuItem);
		}

		/// <summary>
		/// Registers the command with Visual Studio.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <returns>A task that completes when registration is done.</returns>
		public static async Task InitializeAsync(AsyncPackage package)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;

			if (commandService == null)
			{
				return;
			}

			_ = new OpenSolutionSecurityReviewCommand(package, commandService);
		}

		/// <summary>
		/// Executes the command.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void Execute(object? sender, EventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.ExecuteAsync().ConfigureAwait(false);
			}).FileAndForget(nameof(OpenSolutionSecurityReviewCommand));
		}

		/// <summary>
		/// Updates command visibility and enabled state before the menu is displayed.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Event arguments.</param>
		private void OnBeforeQueryStatus(object sender, EventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (sender is not OleMenuCommand menuCommand)
			{
				return;
			}

			menuCommand.Visible = true;
			menuCommand.Enabled = SolutionDiscoveryService.HasOpenSolution();
		}

		/// <summary>
		/// Resolves the open solution, runs the scanner, and shows the Solution Security Review tool window.
		/// </summary>
		/// <returns>A task that completes when the review window is shown.</returns>
		private async Task ExecuteAsync()
		{
			var solutionPath = await SolutionDiscoveryService.GetOpenSolutionPathAsync(this.package).ConfigureAwait(false);

			if (string.IsNullOrWhiteSpace(solutionPath) || !File.Exists(solutionPath))
			{
				await this.package.ShowSolutionSecurityReviewAsync(null, null);
				return;
			}

			var scanPath = solutionPath!;
			var report   = await this.scannerService.ScanSolutionAsync(scanPath, this.package.DisposalToken).ConfigureAwait(false);

			this.package.UpdateLatestScanReport(report);
			await this.package.ShowSolutionSecurityReviewAsync(scanPath, report).ConfigureAwait(false);
		}
	}
}
