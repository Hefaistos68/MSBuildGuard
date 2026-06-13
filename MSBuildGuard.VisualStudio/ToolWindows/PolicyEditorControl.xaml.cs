using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Interaction logic for the policy editor control.
	/// </summary>
	public partial class PolicyEditorControl : UserControl
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="PolicyEditorControl"/> class.
		/// </summary>
		public PolicyEditorControl()
		{
			this.InitializeComponent();
			this.DataContext = new PolicyEditorViewModel();
		}

		/// <summary>
		/// Loads policy context into the editor.
		/// </summary>
		/// <param name="solutionPath">The currently open solution path.</param>
		/// <param name="projectPaths">All loaded project paths available for project-scoped editing.</param>
		/// <param name="preferredPolicyType">Preferred policy scope to select when available.</param>
		internal void LoadPolicyContext(string solutionPath, IReadOnlyList<string> projectPaths, PolicyEditorViewModel.PolicyScopeType? preferredPolicyType)
		{
			if (this.DataContext is PolicyEditorViewModel viewModel)
			{
				viewModel.LoadContext(solutionPath, projectPaths, preferredPolicyType);
			}
		}

		/// <summary>
		/// Handles the Save button click.
		/// </summary>
		/// <param name="sender">The button.</param>
		/// <param name="e">Event arguments.</param>
		private void OnSaveClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(this.OnSaveClickAsync).FileAndForget(nameof(PolicyEditorControl));
		}

		/// <summary>
		/// Asynchronously validates and saves the current policy edits, triggering a rescan if successful.
		/// </summary>
		/// <returns>A task that completes when the save workflow finishes.</returns>
		private async System.Threading.Tasks.Task OnSaveClickAsync()
		{
			if (this.DataContext is not PolicyEditorViewModel viewModel)
			{
				return;
			}

			if (!viewModel.HasPolicyChanges())
			{
				viewModel.StatusMessage = "No policy changes detected.";
				return;
			}

			if (viewModel.IsCurrentPolicyMorePermissive())
			{
				var confirmation = MessageBox.Show(
					"The updated policy is more permissive than the currently loaded policy. Do you still want to save it?",
					"More permissive policy detected",
					MessageBoxButton.YesNo,
					MessageBoxImage.Warning);

				if (confirmation != MessageBoxResult.Yes)
				{
					viewModel.StatusMessage = "Save canceled.";
					return;
				}
			}

			var saved = await viewModel.SaveAsync().ConfigureAwait(true);

			if (!saved)
			{
				return;
			}

			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
			{
				await package.OnPolicyChangedRescanAsync();
			}
		}

		/// <summary>
		/// Handles a mouse click on the policy path label by navigating to the policy file in the editor.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Mouse button event arguments.</param>
		private void OnPolicyPathClick(object sender, MouseButtonEventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (this.DataContext is not PolicyEditorViewModel viewModel)
			{
				return;
			}

			if (string.IsNullOrWhiteSpace(viewModel.PolicyPath) || !File.Exists(viewModel.PolicyPath))
			{
				viewModel.StatusMessage = "Policy file does not exist yet. Save to create it.";
				return;
			}

			if (MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
			{
				return;
			}

			FindingNavigationService.Navigate(package, viewModel.PolicyPath, 1, 1);
		}
	}
}
