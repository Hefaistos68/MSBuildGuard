using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using Microsoft.VisualStudio.PlatformUI;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Dialog for managing trusted certificate signers.
	/// Signers are added via the Assembly Information dialog; this dialog only allows removal.
	/// </summary>
	public partial class ManageSignerTrustsDialog : DialogWindow
	{
		private readonly ManageSignerTrustsHelper helper;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageSignerTrustsDialog"/> class.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="projectPath">Current project path.</param>
		public ManageSignerTrustsDialog(string solutionPath = "", string projectPath = "")
		{
			this.helper = new ManageSignerTrustsHelper(solutionPath, projectPath);
			this.InitializeComponent();
			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted signers.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			IReadOnlyList<string> loadedProjectPaths = Array.Empty<string>();

			try
			{
				loadedProjectPaths = SolutionExplorerProjectDiscoveryService.GetLoadedProjectPaths();
			}
			catch
			{
				// Keep project selector empty when project discovery is unavailable.
			}

			this.helper.InitializeProjectOptions(loadedProjectPaths);
			this.InitializeScopeOptions();
			this.LoadTrustedSigners();

			TrustedSignersGrid.ItemsSource = this.helper.TrustedSigners;
			TrustedSignersGrid.SelectionChanged += (s, args) => this.UpdateRemoveButtonState();
		}

		/// <summary>
		/// Wires context menu open handlers when the trusted signers grid is loaded.
		/// </summary>
		private void TrustedSignersGrid_Loaded(object sender, RoutedEventArgs e)
		{
			if (TrustedSignersGrid.ContextMenu != null)
			{
				TrustedSignersGrid.ContextMenu.Opened -= this.TrustedSignersContextMenu_Opened;
				TrustedSignersGrid.ContextMenu.Opened += this.TrustedSignersContextMenu_Opened;
			}
		}

		/// <summary>
		/// Initializes available trust scopes and related project selector state.
		/// </summary>
		private void InitializeScopeOptions()
		{
			var scopes = new List<TrustScope> { TrustScope.User };

			if (!string.IsNullOrWhiteSpace(this.helper.SolutionPath))
			{
				scopes.Add(TrustScope.Solution);
			}

			if (this.helper.ProjectOptions.Count > 0)
			{
				scopes.Add(TrustScope.Project);
			}

			ScopeComboBox.ItemsSource  = scopes;
			ScopeComboBox.SelectedItem = TrustScope.User;
			ProjectScopeComboBox.ItemsSource = this.helper.ProjectOptions;

			if (this.helper.ProjectOptions.Count > 0)
			{
				var preferred = this.helper.ProjectOptions.FirstOrDefault(option => string.Equals(option.Path, this.helper.ProjectPath, StringComparison.OrdinalIgnoreCase));

				ProjectScopeComboBox.SelectedItem = preferred ?? this.helper.ProjectOptions.First();
			}
		}

		/// <summary>
		/// Handles scope selection changes and reloads signer trusts for the selected scope.
		/// </summary>
		private void ScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!this.IsLoaded)
			{
				return;
			}

			ProjectSelectorPanel.Visibility = this.GetSelectedScope() == TrustScope.Project ? Visibility.Visible : Visibility.Collapsed;
			this.helper.ClearChanges();
			this.LoadTrustedSigners();
		}

		/// <summary>
		/// Handles project selection changes for project-scoped trust management.
		/// </summary>
		private void ProjectScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!this.IsLoaded || this.GetSelectedScope() != TrustScope.Project)
			{
				return;
			}

			this.helper.ClearChanges();
			this.LoadTrustedSigners();
		}

		/// <summary>
		/// Loads all signer-scoped trust entries from the trust store.
		/// </summary>
		private void LoadTrustedSigners()
		{
			try
			{
				this.helper.LoadTrustedSigners(this.GetSelectedScope(), this.GetSelectedProjectPathForScope());
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error loading trusted signers: {ex.Message}", "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Updates the enabled state of the Remove button based on current selection.
		/// </summary>
		private void UpdateRemoveButtonState()
		{
			RemoveButton.IsEnabled = TrustedSignersGrid.SelectedItem != null;
		}

		/// <summary>
		/// Handles the Remove button click to remove the selected signer trust.
		/// </summary>
		private void RemoveButton_Click(object sender, RoutedEventArgs e)
		{
			if (TrustedSignersGrid.SelectedItem is not SignerTrustItem selected)
			{
				return;
			}

			var result = MessageBox.Show(
				$"Remove trust for signer '{selected.SignerName}'?\n\nAssemblies signed by this certificate will no longer be automatically approved.",
				"Confirm Removal",
				MessageBoxButton.OKCancel,
				MessageBoxImage.Question);

			if (result != MessageBoxResult.OK)
			{
				return;
			}

			this.helper.RemoveTrustedSigner(selected);
			this.UpdateRemoveButtonState();
		}

		/// <summary>
		/// Handles context-menu requests to move selected signer trust to user or solution scope.
		/// </summary>
		private void MoveTrustToScopeMenuItem_Click(object sender, RoutedEventArgs e)
		{
			if (sender is not MenuItem menuItem || menuItem.Tag is not string targetScopeText || !Enum.TryParse(targetScopeText, out TrustScope targetScope))
			{
				return;
			}

			if (TrustedSignersGrid.SelectedItem is not SignerTrustItem selectedTrust)
			{
				return;
			}

			this.MoveTrustToScope(selectedTrust, targetScope, this.helper.ProjectPath);
		}

		/// <summary>
		/// Handles context-menu requests to move selected signer trust to a specific project scope.
		/// </summary>
		private void MoveTrustToProjectScopeMenuItem_Click(object sender, RoutedEventArgs e)
		{
			if (sender is not MenuItem menuItem || menuItem.Tag is not string targetProjectPath || string.IsNullOrWhiteSpace(targetProjectPath))
			{
				return;
			}

			if (TrustedSignersGrid.SelectedItem is not SignerTrustItem selectedTrust)
			{
				return;
			}

			this.MoveTrustToScope(selectedTrust, TrustScope.Project, targetProjectPath);
		}

		/// <summary>
		/// Updates context menu command enabled states based on current selection and scope availability.
		/// </summary>
		private void TrustedSignersContextMenu_Opened(object sender, RoutedEventArgs e)
		{
			if (sender is not ContextMenu contextMenu)
			{
				return;
			}

			var hasSelection = TrustedSignersGrid.SelectedItem is SignerTrustItem;

			foreach (var item in contextMenu.Items.OfType<MenuItem>())
			{
				if (item.Header is string header && header.Contains("User", StringComparison.OrdinalIgnoreCase))
				{
					item.IsEnabled = hasSelection && this.GetSelectedScope() != TrustScope.User;
				}
				else if (item.Header is string solutionHeader && solutionHeader.Contains("Solution", StringComparison.OrdinalIgnoreCase))
				{
					item.IsEnabled = hasSelection && !string.IsNullOrWhiteSpace(this.helper.SolutionPath) && this.GetSelectedScope() != TrustScope.Solution;
				}
				else
				{
					item.IsEnabled = hasSelection && this.helper.ProjectOptions.Count > 0;
				}
			}
		}

		/// <summary>
		/// Moves a signer trust entry from the current scope store to the requested target scope store.
		/// </summary>
		private void MoveTrustToScope(SignerTrustItem selectedTrust, TrustScope targetScope, string targetProjectPath)
		{
			var sourceScope = this.GetSelectedScope();

			if (sourceScope == targetScope)
			{
				return;
			}

			if (targetScope == TrustScope.Solution && string.IsNullOrWhiteSpace(this.helper.SolutionPath))
			{
				MessageBox.Show("Solution scope is not available in this context.", "Move Trust", MessageBoxButton.OK, MessageBoxImage.Information);

				return;
			}

			if (targetScope == TrustScope.Project && string.IsNullOrWhiteSpace(targetProjectPath))
			{
				MessageBox.Show("Project scope is not available in this context.", "Move Trust", MessageBoxButton.OK, MessageBoxImage.Information);

				return;
			}

			try
			{
				var userSid = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				this.helper.MoveTrustToScope(selectedTrust, sourceScope, targetScope, this.GetSelectedProjectPathForScope(), targetProjectPath, userSid);
				MessageBox.Show($"Moved signer trust '{selectedTrust.SignerName}' to {targetScope} scope.", "Trust Moved", MessageBoxButton.OK, MessageBoxImage.Information);
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error moving signer trust scope: {ex.Message}", "Move Failed", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Handles the Save button click to persist changes to the trust store.
		/// </summary>
		private void SaveButton_Click(object sender, RoutedEventArgs e)
		{
			if (!this.helper.HasChanges)
			{
				this.DialogResult = false;
				this.Close();

				return;
			}

			try
			{
				var userSid = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				this.helper.Save(userSid);
				this.DialogResult = true;
				this.Close();
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error saving signer trusts: {ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Handles the Cancel button click.
		/// </summary>
		private void CancelButton_Click(object sender, RoutedEventArgs e)
		{
			this.DialogResult = false;
			this.Close();
		}

		/// <inheritdoc/>
		protected override void OnClosed(EventArgs e)
		{
			base.OnClosed(e);

			if (!this.helper.HasMovedTrust)
			{
				return;
			}

			if (MSBuildGuardPackage.Instance == null)
			{
				return;
			}

			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await MSBuildGuardPackage.Instance.RescanSolutionSecurityReviewAsync();
			}).FileAndForget(nameof(ManageSignerTrustsDialog));
		}

		/// <summary>
		/// Gets the currently selected trust scope from the scope selector.
		/// </summary>
		private TrustScope GetSelectedScope()
		{
			return ScopeComboBox?.SelectedItem is TrustScope scope ? scope : TrustScope.User;
		}

		/// <summary>
		/// Gets the currently selected project path for project-scoped trust operations.
		/// </summary>
		private string GetSelectedProjectPathForScope()
		{
			return ProjectScopeComboBox?.SelectedValue as string ?? this.helper.ProjectPath;
		}
	}
}
