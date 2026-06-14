using System;
using System.ComponentModel.Design;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Task = System.Threading.Tasks.Task;

namespace MSBuildGuard.VisualStudio.Commands
{
	/// <summary>
	/// Implements the command that opens the Manage Assembly Trusts dialog.
	/// </summary>
	internal sealed class ManageAssemblyTrustsCommand
	{
		private readonly MSBuildGuardPackage package;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageAssemblyTrustsCommand"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <param name="commandService">Menu command service.</param>
		private ManageAssemblyTrustsCommand(AsyncPackage package, OleMenuCommandService commandService)
		{
			this.package = (MSBuildGuardPackage)package;

			var menuCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.ManageAssemblyTrustsCommandId);
			var menuItem      = new OleMenuCommand(this.Execute, menuCommandId);

			menuItem.BeforeQueryStatus += this.OnBeforeQueryStatus;
			commandService.AddCommand(menuItem);
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

			_ = new ManageAssemblyTrustsCommand(package, commandService);
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
			menuCommand.Enabled = Services.SolutionDiscoveryService.HasOpenSolution();
		}

		/// <summary>
		/// Executes the command by opening the Manage Assembly Trusts dialog.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void Execute(object? sender, EventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.package.ShowManageAssemblyTrustsAsync().ConfigureAwait(false);
			}).FileAndForget(nameof(ManageAssemblyTrustsCommand));
		}
	}
}
