using System;
using System.ComponentModel.Design;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Task = System.Threading.Tasks.Task;

namespace MSBuildGuard.VisualStudio.Commands
{
	/// <summary>
	/// Implements the command that opens the Policy Editor tool window.
	/// </summary>
	internal sealed class EditPolicyCommand
	{
		private readonly MSBuildGuardPackage package;

		/// <summary>
		/// Initializes a new instance of the <see cref="EditPolicyCommand"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <param name="commandService">Menu command service.</param>
		private EditPolicyCommand(AsyncPackage package, OleMenuCommandService commandService)
		{
			this.package = (MSBuildGuardPackage)package;

			var menuCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.EditPolicyCommandId);
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

			_ = new EditPolicyCommand(package, commandService);
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
		/// Executes the command by opening the Policy Editor tool window.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void Execute(object? sender, EventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.package.ShowPolicyEditorAsync().ConfigureAwait(false);
			}).FileAndForget(nameof(EditPolicyCommand));
		}
	}
}
