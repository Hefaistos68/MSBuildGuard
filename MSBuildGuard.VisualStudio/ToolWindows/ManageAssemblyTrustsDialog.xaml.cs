using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
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
	public partial class ManageAssemblyTrustsDialog : Window
	{
		private readonly string solutionPath;
		private readonly string projectPath;
		private readonly ObservableCollection<SolutionProjectOptionViewModel> projectOptions = new();
		private ObservableCollection<AssemblyTrustItem> trustedAssemblies = new();
		private string trustStorePath = string.Empty;
		private bool hasChanges = false;
		private bool hasMovedTrust = false;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageAssemblyTrustsDialog"/> class.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="projectPath">Current project path.</param>
		public ManageAssemblyTrustsDialog(string solutionPath = "", string projectPath = "")
		{
			this.solutionPath = solutionPath ?? string.Empty;
			this.projectPath  = projectPath ?? string.Empty;
			InitializeComponent();
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted assemblies.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			InitializeProjectOptions();
			InitializeScopeOptions();
			LoadTrustedAssemblies();
			TrustedAssembliesGrid.ItemsSource = trustedAssemblies;
			TrustedAssembliesGrid.SelectionChanged += (s, args) => UpdateRemoveButtonState();
		}

		private void TrustedAssembliesGrid_Loaded(object sender, RoutedEventArgs e)
		{
			if (TrustedAssembliesGrid.ContextMenu != null)
			{
				TrustedAssembliesGrid.ContextMenu.Opened -= TrustedAssembliesContextMenu_Opened;
				TrustedAssembliesGrid.ContextMenu.Opened += TrustedAssembliesContextMenu_Opened;
			}
		}

		private void InitializeScopeOptions()
		{
			var scopes = new List<TrustScope> { TrustScope.User };

			if (!string.IsNullOrWhiteSpace(this.solutionPath))
			{
				scopes.Add(TrustScope.Solution);
			}

			if (projectOptions.Count > 0)
			{
				scopes.Add(TrustScope.Project);
			}

			ScopeComboBox.ItemsSource = scopes;
			ScopeComboBox.SelectedItem = TrustScope.User;
			ProjectScopeComboBox.ItemsSource = projectOptions;

			if (projectOptions.Count > 0)
			{
				var preferred = projectOptions.FirstOrDefault(option => string.Equals(option.Path, this.projectPath, StringComparison.OrdinalIgnoreCase));
				ProjectScopeComboBox.SelectedItem = preferred ?? projectOptions.First();
			}
		}

		private void InitializeProjectOptions()
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			projectOptions.Clear();

			if (string.IsNullOrWhiteSpace(this.solutionPath))
			{
				return;
			}

			try
			{
				var loadedPaths = SolutionExplorerProjectDiscoveryService.GetLoadedProjectPaths();

				foreach (var loadedPath in loadedPaths.Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.OrdinalIgnoreCase))
				{
					projectOptions.Add(new SolutionProjectOptionViewModel
					{
						Name = System.IO.Path.GetFileNameWithoutExtension(loadedPath),
						Path = loadedPath
					});
				}
			}
			catch
			{
				// Keep project selector empty when project discovery is unavailable.
			}
		}

		private void ScopeComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
		{
			if (!IsLoaded)
			{
				return;
			}

			ProjectSelectorPanel.Visibility = GetSelectedScope() == TrustScope.Project ? Visibility.Visible : Visibility.Collapsed;
			hasChanges = false;
			LoadTrustedAssemblies();
		}

		private void ProjectScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!IsLoaded || GetSelectedScope() != TrustScope.Project)
			{
				return;
			}

			hasChanges = false;
			LoadTrustedAssemblies();
		}

		/// <summary>
		/// Loads all trusted assemblies from the trust store.
		/// </summary>
		private void LoadTrustedAssemblies()
		{
			trustedAssemblies.Clear();

			try
			{
				var trustStoreService = new TrustStoreService();
				trustStorePath = ResolveTrustStorePath(trustStoreService, GetSelectedScope(), this.solutionPath, GetSelectedProjectPathForScope());

				if (!System.IO.File.Exists(trustStorePath))
				{
					// Trust store doesn't exist yet - that's fine, just empty
					return;
				}

				var document = trustStoreService.Load(trustStorePath);

				if (document?.Decisions == null || document.Decisions.Count == 0)
				{
					// No decisions in store - that's fine, just empty
					return;
				}

				// Debug: Check what scopes exist in the store
				var allScopes = document.Decisions.Select(d => d.Scope).Distinct().ToList();

				var assemblyTrusts = document.Decisions
						.Where(d => d.ScopeKind == TrustDecisionScopeKind.Assembly || 
									string.Equals(d.Scope, "Assembly", StringComparison.OrdinalIgnoreCase))
						.GroupBy(d => d.SubjectHash)
						.Select(g =>
						{
							var signer      = g.Select(item => item.AssemblySigner).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
							var issuer      = g.Select(item => item.AssemblyIssuer).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
							var subjectName = g.Select(item => item.AssemblySubject).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

							// If signature data was never saved (e.g. trust created before the fix),
							// resolve the assembly from the NuGet cache and re-read it now.
							if (string.IsNullOrWhiteSpace(signer) && string.IsNullOrWhiteSpace(issuer))
							{
								var name    = ExtractAssemblyName(g.Key);
								var version = ExtractAssemblyVersion(g.Key);
								var dllPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(name, version);

								if (!string.IsNullOrWhiteSpace(dllPath))
								{
									var sig = new AssemblySignatureService().ReadSignature(dllPath);
									signer      = sig.Signer;
									issuer      = sig.Issuer;
									subjectName = sig.Subject;
								}
							}

							return new AssemblyTrustItem
							{
								Name        = ExtractAssemblyName(g.Key),
								Version     = ExtractAssemblyVersion(g.Key),
								Signer      = signer,
								Issuer      = issuer,
								SubjectName = subjectName,
								Reason      = g.FirstOrDefault()?.Reason ?? string.Empty,
								Subject     = g.Key
							};
						})
					.OrderBy(a => a.Name)
					.ThenBy(a => a.Version)
					.ToList();

				foreach (var trust in assemblyTrusts)
				{
					trustedAssemblies.Add(trust);
				}
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error loading trusted assemblies: {ex.Message}", "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Extracts the assembly name from the subject identifier (name@version format).
		/// </summary>
		private static string ExtractAssemblyName(string subject)
		{
			var parts = subject.Split('@');
			return parts.Length > 0 ? parts[0] : subject;
		}

		/// <summary>
		/// Extracts the assembly version from the subject identifier (name@version format).
		/// </summary>
		private static string ExtractAssemblyVersion(string subject)
		{
			var parts = subject.Split('@');
			return parts.Length > 1 ? parts[1] : string.Empty;
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
			// Prompt user to select an assembly file
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

			var assemblyPath = openFileDialog.FileName;

			// Extract assembly information from the selected file
			string assemblyName;
			string assemblyVersion;
			var signature = new AssemblySignatureService().ReadSignature(assemblyPath);

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

			// Show trust confirmation dialog
			var trustDialog = new TrustAssemblyDialog
			{
				AssemblyName           = assemblyName,
				AssemblyVersion        = assemblyVersion,
				AssemblyPath           = assemblyPath,
				AssemblySigner         = signature.Signer,
				AssemblyIssuer         = signature.Issuer,
				AssemblySubject        = signature.Subject,
				SolutionPath           = this.solutionPath,
				ProjectPath            = this.projectPath,
				Owner                  = this,
				WindowStartupLocation  = WindowStartupLocation.CenterOwner
			};

			var result = trustDialog.ShowDialog();

			if (result != true)
			{
				return;
			}

			var existingTrust = trustedAssemblies.FirstOrDefault(a => a.Name == assemblyName && a.Version == assemblyVersion);

			if (existingTrust != null)
			{
				MessageBox.Show(
					$"Assembly '{assemblyName}' version '{assemblyVersion}' is already trusted.",
					"Duplicate",
					MessageBoxButton.OK,
					MessageBoxImage.Information);
				return;
			}

			var newTrust = new AssemblyTrustItem
			{
				Name        = assemblyName,
				Version     = assemblyVersion,
				Signer      = trustDialog.AssemblySigner,
				Issuer      = trustDialog.AssemblyIssuer,
				SubjectName = trustDialog.AssemblySubject,
				Reason      = trustDialog.TrustReason,
				Subject     = $"{assemblyName}@{assemblyVersion}"
			};

			trustedAssemblies.Add(newTrust);
			hasChanges = true;
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

			trustedAssemblies.Remove(selectedTrust);
			hasChanges = true;
			UpdateRemoveButtonState();
		}

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

			MoveTrustToScope(selectedTrust, targetScope, this.projectPath);
		}

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

			MoveTrustToScope(selectedTrust, TrustScope.Project, targetProjectPath);
		}

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
					item.IsEnabled = hasSelection && GetSelectedScope() != TrustScope.User;
				}
				else if (item.Header is string solutionHeader && solutionHeader.Contains("Solution", StringComparison.OrdinalIgnoreCase))
				{
					item.IsEnabled = hasSelection && !string.IsNullOrWhiteSpace(this.solutionPath) && GetSelectedScope() != TrustScope.Solution;
				}
				else
				{
					item.IsEnabled = hasSelection && projectOptions.Count > 0;
				}
			}
		}

		private void MoveTrustToScope(AssemblyTrustItem selectedTrust, TrustScope targetScope, string targetProjectPath)
		{
			var sourceScope = GetSelectedScope();

			if (sourceScope == targetScope)
			{
				return;
			}

			if (targetScope == TrustScope.Solution && string.IsNullOrWhiteSpace(this.solutionPath))
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
				var trustStoreService = new TrustStoreService();
				var sourceProjectPath = sourceScope == TrustScope.Project ? GetSelectedProjectPathForScope() : this.projectPath;
				var selectedTargetProjectPath = targetScope == TrustScope.Project ? targetProjectPath : this.projectPath;
				var sourcePath = ResolveTrustStorePath(trustStoreService, sourceScope, this.solutionPath, sourceProjectPath);
				var targetPath = ResolveTrustStorePath(trustStoreService, targetScope, this.solutionPath, selectedTargetProjectPath);
				var userSid = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				if (string.Equals(sourcePath, targetPath, StringComparison.OrdinalIgnoreCase))
				{
					return;
				}

				var sourceStore = trustStoreService.Load(sourcePath);
				var sourceEntries = sourceStore.Decisions
					.Where(d => (d.ScopeKind == TrustDecisionScopeKind.Assembly || string.Equals(d.Scope, "Assembly", StringComparison.OrdinalIgnoreCase)) && string.Equals(d.SubjectHash, selectedTrust.Subject, StringComparison.OrdinalIgnoreCase))
					.ToList();

				if (sourceEntries.Count == 0)
				{
					return;
				}

				var moveReason = $"Moved assembly trust from {sourceScope} to {targetScope}";

				foreach (var sourceEntry in sourceEntries)
				{
					var movedEntryReason = string.IsNullOrWhiteSpace(sourceEntry.Reason)
						? moveReason
						: $"{sourceEntry.Reason} ({moveReason})";

					trustStoreService.AddDecision(targetPath, new TrustDecisionEntry
					{
						DecisionId           = Guid.NewGuid().ToString("N"),
						Scope                = sourceEntry.Scope,
						SubjectHash          = sourceEntry.SubjectHash,
						AssemblySigner       = sourceEntry.AssemblySigner,
						AssemblyIssuer       = sourceEntry.AssemblyIssuer,
						AssemblySubject      = sourceEntry.AssemblySubject,
						AssemblyThumbprint   = sourceEntry.AssemblyThumbprint,
						AssemblySerialNumber = sourceEntry.AssemblySerialNumber,
						Decision             = sourceEntry.Decision,
						Reason               = movedEntryReason,
						UserSid              = userSid,
						CreatedAtUtc         = DateTimeOffset.UtcNow,
						ExpiresAtUtc         = sourceEntry.ExpiresAtUtc,
						RepositoryRemote     = sourceEntry.RepositoryRemote,
						Branch               = sourceEntry.Branch,
						CommitSha            = sourceEntry.CommitSha,
						PolicyProfile        = sourceEntry.PolicyProfile
					});
				}

				trustStoreService.RemoveDecisionsBySubject(sourcePath, selectedTrust.Subject, moveReason, userSid);

				trustedAssemblies.Remove(selectedTrust);
				hasMovedTrust = true;
				MessageBox.Show($"Moved trust '{selectedTrust.Name}@{selectedTrust.Version}' to {targetScope} scope.", "Trust Moved", MessageBoxButton.OK, MessageBoxImage.Information);
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error moving trust scope: {ex.Message}", "Move Failed", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Handles the Save button click to persist changes to the trust store.
		/// </summary>
		private void SaveButton_Click(object sender, RoutedEventArgs e)
		{
			if (!hasChanges)
			{
				DialogResult = false;
				Close();
				return;
			}

			try
			{
				var trustStoreService = new TrustStoreService();

				// Ensure we have the correct trust store path
				if (string.IsNullOrWhiteSpace(trustStorePath))
				{
					trustStorePath = trustStoreService.GetDefaultUserTrustPath();
				}

				var document = trustStoreService.Load(trustStorePath);
				var userSid  = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				if (document?.Decisions == null)
				{
					document = new TrustStoreDocument { Decisions = new List<TrustDecisionEntry>() };
				}

				// Remove all existing assembly trusts
				var existingAssemblyTrusts = document.Decisions
					.Where(d => d.ScopeKind == TrustDecisionScopeKind.Assembly || 
								string.Equals(d.Scope, "Assembly", StringComparison.OrdinalIgnoreCase))
					.ToList();

				foreach (var existingTrust in existingAssemblyTrusts)
				{
					document.Decisions.Remove(existingTrust);
				}

				// Add the new set of assembly trusts
				foreach (var trust in trustedAssemblies)
				{
					var entry = new TrustDecisionEntry
					{
						DecisionId      = Guid.NewGuid().ToString(),
						Scope           = "Assembly",
						SubjectHash     = trust.Subject,
						AssemblySigner  = trust.Signer,
						AssemblyIssuer  = trust.Issuer,
						AssemblySubject = trust.SubjectName,
						Decision        = "Trust",
						Reason          = trust.Reason,
						UserSid         = userSid,
						CreatedAtUtc    = DateTimeOffset.UtcNow
					};

					document.Decisions.Add(entry);
				}

				trustStoreService.Save(trustStorePath, document);
				DialogResult = true;
				Close();
			}
			catch (Exception ex)
			{
				MessageBox.Show($"Error saving assembly trusts: {ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		/// <summary>
		/// Handles the Cancel button click.
		/// </summary>
		private void CancelButton_Click(object sender, RoutedEventArgs e)
		{
			DialogResult = false;
			Close();
		}

		/// <inheritdoc/>
		protected override void OnClosed(EventArgs e)
		{
			base.OnClosed(e);

			if (!hasMovedTrust)
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
		/// Gets the currently selected trust scope from the UI.
		/// </summary>
		/// <returns></returns>
		private TrustScope GetSelectedScope()
		{
			return ScopeComboBox?.SelectedItem is TrustScope scope ? scope : TrustScope.User;
		}

		/// <summary>
		/// Gets the currently selected project path for the project scope, if applicable.
		/// </summary>
		/// <returns></returns>
		private string GetSelectedProjectPathForScope()
		{
			return ProjectScopeComboBox?.SelectedValue as string ?? this.projectPath;
		}

		/// <summary>
		/// Resolves the appropriate trust store path based on the selected scope and context.
		/// </summary>
		/// <param name="trustStoreService">The trust store service used to resolve paths.</param>
		/// <param name="scope">The selected trust scope.</param>
		/// <param name="solutionPath">The path to the solution.</param>
		/// <param name="projectPath">The path to the project.</param>
		/// <returns>The resolved trust store path.</returns>
		private static string ResolveTrustStorePath(TrustStoreService trustStoreService, TrustScope scope, string solutionPath, string projectPath)
		{
			if (scope == TrustScope.Project && !string.IsNullOrWhiteSpace(projectPath))
			{
				return trustStoreService.GetProjectTrustPath(projectPath);
			}

			if (scope == TrustScope.Solution && !string.IsNullOrWhiteSpace(solutionPath))
			{
				return trustStoreService.GetSolutionTrustPath(solutionPath);
			}

			return trustStoreService.GetDefaultUserTrustPath();
		}
	}

	/// <summary>
	/// Represents a single trusted assembly item in the list.
	/// </summary>
	internal sealed class AssemblyTrustItem
	{
		/// <summary>
		/// Gets or sets the assembly name.
		/// </summary>
		public string Name { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly version.
		/// </summary>
		public string Version { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly signer.
		/// </summary>
		public string Signer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate issuer.
		/// </summary>
		public string Issuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate subject.
		/// </summary>
		public string SubjectName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the trust reason.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the subject identifier (name@version).
		/// </summary>
		public string Subject { get; set; } = string.Empty;
	}
}
