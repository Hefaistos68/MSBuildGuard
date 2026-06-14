using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
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
	/// Dialog for managing trusted assemblies.
	/// </summary>
	public partial class ManageAssemblyTrustsDialog : DialogWindow
	{
		private readonly ManageAssemblyTrustsHelper helper;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageAssemblyTrustsDialog"/> class.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="projectPath">Current project path.</param>
		public ManageAssemblyTrustsDialog(string solutionPath = "", string projectPath = "")
		{
			this.helper = new ManageAssemblyTrustsHelper(solutionPath, projectPath);
			this.InitializeComponent();
			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted assemblies.
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
			this.LoadTrustedAssemblies();

			TrustedAssembliesGrid.ItemsSource = this.helper.TrustedAssemblies;
			TrustedAssembliesGrid.SelectionChanged += (s, args) => this.UpdateRemoveButtonState();
		}

		/// <summary>
		/// Wires context menu open handlers when the trusted assemblies grid is loaded.
		/// </summary>
		private void TrustedAssembliesGrid_Loaded(object sender, RoutedEventArgs e)
		{
			if (TrustedAssembliesGrid.ContextMenu != null)
			{
				TrustedAssembliesGrid.ContextMenu.Opened -= this.TrustedAssembliesContextMenu_Opened;
				TrustedAssembliesGrid.ContextMenu.Opened += this.TrustedAssembliesContextMenu_Opened;
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
		/// Handles scope selection changes and reloads assembly trusts for the selected scope.
		/// </summary>
		private void ScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!this.IsLoaded)
			{
				return;
			}

			ProjectSelectorPanel.Visibility = this.GetSelectedScope() == TrustScope.Project ? Visibility.Visible : Visibility.Collapsed;
			this.helper.ClearChanges();
			this.LoadTrustedAssemblies();
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
			this.LoadTrustedAssemblies();
		}

		/// <summary>
		/// Loads all trusted assemblies from the trust store.
		/// </summary>
		private void LoadTrustedAssemblies()
		{
			try
			{
				this.helper.LoadTrustedAssemblies(this.GetSelectedScope(), this.GetSelectedProjectPathForScope());
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error loading trusted assemblies: {ex.Message}", "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Updates the enabled state of the Remove button based on selection.
		/// </summary>
		private void UpdateRemoveButtonState()
		{
			RemoveButton.IsEnabled = TrustedAssembliesGrid.SelectedItem != null;
		}

		/// <summary>
		/// Handles the Add button click to add a new assembly trust.
		/// </summary>
		private void AddButton_Click(object sender, RoutedEventArgs e)
		{
			var openFileDialog = new OpenFileDialog
			{
				Title       = "Select Assembly File",
				Filter      = "Assembly Files (*.dll;*.exe)|*.dll;*.exe|All Files (*.*)|*.*",
				Multiselect = false
			};

			if (openFileDialog.ShowDialog(this) != true)
			{
				return;
			}

			var assemblyPath     = openFileDialog.FileName;
			string assemblyName;
			string assemblyVersion;
			var signature        = new AssemblySignatureService().ReadSignature(assemblyPath);

			try
			{
				var assemblyName_obj = AssemblyName.GetAssemblyName(assemblyPath);

				assemblyName    = assemblyName_obj.Name ?? string.Empty;
				assemblyVersion = assemblyName_obj.Version?.ToString() ?? "Unknown";
			}
			catch (Exception ex)
			{
				MessageBox.Show(
					$"Unable to read assembly information: {ex.Message}",
					"Error Reading Assembly",
					MessageBoxButton.OK,
					MessageBoxImage.Error);

				return;
			}

			if (string.IsNullOrWhiteSpace(assemblyName))
			{
				MessageBox.Show(
					"Unable to determine assembly name from the selected file.",
					"Invalid Assembly",
					MessageBoxButton.OK,
					MessageBoxImage.Warning);

				return;
			}

			var trustDialog = new TrustAssemblyDialog
			{
				AssemblyName          = assemblyName,
				AssemblyVersion       = assemblyVersion,
				AssemblyPath          = assemblyPath,
				AssemblySigner        = signature.Signer,
				AssemblyIssuer        = signature.Issuer,
				AssemblySubject       = signature.Subject,
				SolutionPath          = this.helper.SolutionPath,
				ProjectPath           = this.helper.ProjectPath,
				Owner                 = this,
				WindowStartupLocation = WindowStartupLocation.CenterOwner
			};

			var result = trustDialog.ShowDialog();

			if (result != true)
			{
				return;
			}

			var existingTrust = this.helper.TrustedAssemblies.FirstOrDefault(a => a.Name == assemblyName && a.Version == assemblyVersion);

			if (existingTrust != null)
			{
				MessageBox.Show(
					$"Assembly '{assemblyName}' version '{assemblyVersion}' is already trusted.",
					"Duplicate",
					MessageBoxButton.OK,
					MessageBoxImage.Information);

				return;
			}

			this.helper.AddTrustedAssembly(
				assemblyName,
				assemblyVersion,
				trustDialog.AssemblySigner,
				trustDialog.AssemblyIssuer,
				trustDialog.AssemblySubject,
				trustDialog.TrustReason);
		}

		/// <summary>
		/// Handles the Remove button click to remove a selected assembly trust.
		/// </summary>
		private void RemoveButton_Click(object sender, RoutedEventArgs e)
		{
			if (TrustedAssembliesGrid.SelectedItem is not AssemblyTrustItem selectedTrust)
			{
				return;
			}

			var result = MessageBox.Show(
				$"Remove trust for '{selectedTrust.Name}' version '{selectedTrust.Version}'?",
				"Confirm Removal",
				MessageBoxButton.OKCancel,
				MessageBoxImage.Question);

			if (result != MessageBoxResult.OK)
			{
				return;
			}

			this.helper.RemoveTrustedAssembly(selectedTrust);
			this.UpdateRemoveButtonState();
		}

		/// <summary>
		/// Triggers scope relocation from context menu.
		/// </summary>
		private void MoveTrustToScopeMenuItem_Click(object sender, RoutedEventArgs e)
		{
			if (sender is not MenuItem menuItem || menuItem.Tag is not string targetScopeText || !Enum.TryParse(targetScopeText, out TrustScope targetScope))
			{
				return;
			}

			if (TrustedAssembliesGrid.SelectedItem is not AssemblyTrustItem selectedTrust)
			{
				return;
			}

			this.MoveTrustToScope(selectedTrust, targetScope, this.helper.ProjectPath);
		}

		/// <summary>
		/// Triggers project scope relocation from context menu.
		/// </summary>
		private void MoveTrustToProjectScopeMenuItem_Click(object sender, RoutedEventArgs e)
		{
			if (sender is not MenuItem menuItem || menuItem.Tag is not string targetProjectPath || string.IsNullOrWhiteSpace(targetProjectPath))
			{
				return;
			}

			if (TrustedAssembliesGrid.SelectedItem is not AssemblyTrustItem selectedTrust)
			{
				return;
			}

			this.MoveTrustToScope(selectedTrust, TrustScope.Project, targetProjectPath);
		}

		/// <summary>
		/// Configures context menu command state before it opens.
		/// </summary>
		private void TrustedAssembliesContextMenu_Opened(object sender, RoutedEventArgs e)
		{
			if (sender is not ContextMenu contextMenu)
			{
				return;
			}

			var hasSelection = TrustedAssembliesGrid.SelectedItem is AssemblyTrustItem;

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
		/// Relocates a trust decision from the active scope to the target scope.
		/// </summary>
		private void MoveTrustToScope(AssemblyTrustItem selectedTrust, TrustScope targetScope, string targetProjectPath)
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
		/// Saves changes to the trust store.
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
				MessageBox.Show($"Error saving assembly trusts: {ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
			}).FileAndForget(nameof(ManageAssemblyTrustsDialog));
		}

		/// <summary>
		/// Gets the currently selected trust scope.
		/// </summary>
		private TrustScope GetSelectedScope()
		{
			return ScopeComboBox?.SelectedItem is TrustScope scope ? scope : TrustScope.User;
		}

		/// <summary>
		/// Gets the currently selected project path for project-scoped trust.
		/// </summary>
		private string GetSelectedProjectPathForScope()
		{
			return ProjectScopeComboBox?.SelectedValue as string ?? this.helper.ProjectPath;
		}
	}
}
