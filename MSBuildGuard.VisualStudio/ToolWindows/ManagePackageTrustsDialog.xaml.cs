using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using Microsoft.VisualStudio.PlatformUI;
using Microsoft.VisualStudio.Shell;
using Microsoft.Win32;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Dialog for managing trusted packages by directory hash.
	/// </summary>
	public partial class ManagePackageTrustsDialog : DialogWindow
	{
		private readonly ManagePackageTrustsHelper helper;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManagePackageTrustsDialog"/> class.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="projectPath">Current project path.</param>
		public ManagePackageTrustsDialog(string solutionPath = "", string projectPath = "")
		{
			this.helper = new ManagePackageTrustsHelper(solutionPath, projectPath);
			this.InitializeComponent();
			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted packages.
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
			this.LoadTrustedPackages();

			TrustedPackagesGrid.ItemsSource = this.helper.TrustedPackages;
			TrustedPackagesGrid.SelectionChanged += (s, args) => this.UpdateRemoveButtonState();
		}

		/// <summary>
		/// Handles loading context menu for the package data grid.
		/// </summary>
		private void TrustedPackagesGrid_Loaded(object sender, RoutedEventArgs e)
		{
			if (TrustedPackagesGrid.ContextMenu != null)
			{
				TrustedPackagesGrid.ContextMenu.Opened -= this.TrustedPackagesContextMenu_Opened;
				TrustedPackagesGrid.ContextMenu.Opened += this.TrustedPackagesContextMenu_Opened;
			}
		}

		/// <summary>
		/// Populates the scope selection options based on the open solution/project state.
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
		/// Refreshes lists when scope changes.
		/// </summary>
		private void ScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!this.IsLoaded)
			{
				return;
			}

			ProjectSelectorPanel.Visibility = this.GetSelectedScope() == TrustScope.Project ? Visibility.Visible : Visibility.Collapsed;
			this.helper.ClearChanges();
			this.LoadTrustedPackages();
		}

		/// <summary>
		/// Refreshes lists when selected project scope changes.
		/// </summary>
		private void ProjectScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!this.IsLoaded || this.GetSelectedScope() != TrustScope.Project)
			{
				return;
			}

			this.helper.ClearChanges();
			this.LoadTrustedPackages();
		}

		/// <summary>
		/// Calls helper to resolve and load packages for current scope.
		/// </summary>
		private void LoadTrustedPackages()
		{
			try
			{
				this.helper.LoadTrustedPackages(this.GetSelectedScope(), this.GetSelectedProjectPathForScope());
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error loading trusted packages: {ex.Message}", "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Updates the enabled state of the remove button.
		/// </summary>
		private void UpdateRemoveButtonState()
		{
			RemoveButton.IsEnabled = TrustedPackagesGrid.SelectedItem != null;
		}

		/// <summary>
		/// Prompts file dialog to choose a nuspec file and adds package trust.
		/// </summary>
		private void AddButton_Click(object sender, RoutedEventArgs e)
		{
			var openFileDialog = new OpenFileDialog
			{
				Title       = "Select NuGet Package Manifest",
				Filter      = "NuGet Manifest Files (*.nuspec)|*.nuspec|All Files (*.*)|*.*",
				Multiselect = false
			};

			if (openFileDialog.ShowDialog(this) != true)
			{
				return;
			}

			var nuspecPath     = openFileDialog.FileName;
			string packageId;
			string packageVersion;

			try
			{
				ManagePackageTrustsHelper.ParseNuspec(nuspecPath, out packageId, out packageVersion);
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Unable to read manifest information: {ex.Message}", "Error Reading Manifest", MessageBoxButton.OK, MessageBoxImage.Error);

				return;
			}

			var packageDir = Path.GetDirectoryName(nuspecPath);

			if (string.IsNullOrWhiteSpace(packageDir))
			{
				MessageBox.Show("Unable to determine package directory from manifest path.", "Invalid Manifest Path", MessageBoxButton.OK, MessageBoxImage.Warning);

				return;
			}

			var trustDialog = new TrustPackageDialog
			{
				PackageId             = packageId,
				PackageVersion        = packageVersion,
				PackagePath           = packageDir,
				SolutionPath          = this.helper.SolutionPath,
				ProjectPath           = this.helper.ProjectPath,
				Owner                 = this,
				WindowStartupLocation = WindowStartupLocation.CenterOwner
			};

			if (trustDialog.ShowDialog() != true)
			{
				return;
			}

			if (this.helper.IsPackageAlreadyTrusted(packageId, packageVersion))
			{
				MessageBox.Show($"Package '{packageId}' version '{packageVersion}' is already trusted.", "Duplicate", MessageBoxButton.OK, MessageBoxImage.Information);

				return;
			}

			this.helper.AddTrustedPackage(packageId, packageVersion, trustDialog.PackageHash, trustDialog.TrustReason);
		}

		/// <summary>
		/// Prompts confirmation dialog to remove package trust.
		/// </summary>
		private void RemoveButton_Click(object sender, RoutedEventArgs e)
		{
			if (TrustedPackagesGrid.SelectedItem is not PackageTrustItem selectedTrust)
			{
				return;
			}

			var result = MessageBox.Show(
				$"Remove trust for package '{selectedTrust.Name}' version '{selectedTrust.Version}'?",
				"Confirm Removal",
				MessageBoxButton.OKCancel,
				MessageBoxImage.Question);

			if (result != MessageBoxResult.OK)
			{
				return;
			}

			this.helper.RemoveTrustedPackage(selectedTrust);
			this.UpdateRemoveButtonState();
		}

		/// <summary>
		/// Triggered when moving trust to scope from context menu.
		/// </summary>
		private void MoveTrustToScopeMenuItem_Click(object sender, RoutedEventArgs e)
		{
			if (sender is not MenuItem menuItem || menuItem.Tag is not string targetScopeText || !Enum.TryParse(targetScopeText, out TrustScope targetScope))
			{
				return;
			}

			if (TrustedPackagesGrid.SelectedItem is not PackageTrustItem selectedTrust)
			{
				return;
			}

			this.MoveTrustToScope(selectedTrust, targetScope, this.helper.ProjectPath);
		}

		/// <summary>
		/// Triggered when moving trust to project scope from context menu.
		/// </summary>
		private void MoveTrustToProjectScopeMenuItem_Click(object sender, RoutedEventArgs e)
		{
			if (sender is not MenuItem menuItem || menuItem.Tag is not string targetProjectPath || string.IsNullOrWhiteSpace(targetProjectPath))
			{
				return;
			}

			if (TrustedPackagesGrid.SelectedItem is not PackageTrustItem selectedTrust)
			{
				return;
			}

			this.MoveTrustToScope(selectedTrust, TrustScope.Project, targetProjectPath);
		}

		/// <summary>
		/// Sets active context menu actions based on active scope.
		/// </summary>
		private void TrustedPackagesContextMenu_Opened(object sender, RoutedEventArgs e)
		{
			if (sender is not ContextMenu contextMenu)
			{
				return;
			}

			var hasSelection = TrustedPackagesGrid.SelectedItem is PackageTrustItem;

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
		/// Invokes helper to move a trust entry to the specified target scope.
		/// </summary>
		private void MoveTrustToScope(PackageTrustItem selectedTrust, TrustScope targetScope, string targetProjectPath)
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
				MessageBox.Show($"Moved trust '{selectedTrust.Name}@{selectedTrust.Version}' to {targetScope} scope.", "Trust Moved", MessageBoxButton.OK, MessageBoxImage.Information);
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error moving trust scope: {ex.Message}", "Move Failed", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Saves changes to the active trust store.
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
				MessageBox.Show($"Error saving package trusts: {ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Closes the dialog.
		/// </summary>
		private void CancelButton_Click(object sender, RoutedEventArgs e)
		{
			this.DialogResult = false;
			this.Close();
		}

		/// <inheritdoc />
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
			}).FileAndForget(nameof(ManagePackageTrustsDialog));
		}

		/// <summary>
		/// Gets the currently selected scope from the UI combo box.
		/// </summary>
		private TrustScope GetSelectedScope()
		{
			return ScopeComboBox?.SelectedItem is TrustScope scope ? scope : TrustScope.User;
		}

		/// <summary>
		/// Gets the project path selected in the project scope combo box, or default project path.
		/// </summary>
		private string GetSelectedProjectPathForScope()
		{
			return ProjectScopeComboBox?.SelectedValue as string ?? this.helper.ProjectPath;
		}
	}
}
