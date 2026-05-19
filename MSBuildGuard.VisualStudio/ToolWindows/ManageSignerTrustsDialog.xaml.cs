using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Dialog for managing trusted certificate signers.
	/// Signers are added via the Assembly Information dialog; this dialog only allows removal.
	/// </summary>
	public partial class ManageSignerTrustsDialog : Window
	{
		private readonly string solutionPath;
		private readonly string projectPath;
		private readonly ObservableCollection<SolutionProjectOptionViewModel> projectOptions = new();
		private ObservableCollection<SignerTrustItem> trustedSigners = new();
		private string trustStorePath = string.Empty;
		private bool hasChanges = false;
		private bool hasMovedTrust = false;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageSignerTrustsDialog"/> class.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="projectPath">Current project path.</param>
		public ManageSignerTrustsDialog(string solutionPath = "", string projectPath = "")
		{
			this.solutionPath = solutionPath ?? string.Empty;
			this.projectPath  = projectPath ?? string.Empty;
			InitializeComponent();
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted signers.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			InitializeProjectOptions();
			InitializeScopeOptions();
			LoadTrustedSigners();
			TrustedSignersGrid.ItemsSource = trustedSigners;
			TrustedSignersGrid.SelectionChanged += (s, args) => UpdateRemoveButtonState();
		}

		private void TrustedSignersGrid_Loaded(object sender, RoutedEventArgs e)
		{
			if (TrustedSignersGrid.ContextMenu != null)
			{
				TrustedSignersGrid.ContextMenu.Opened -= TrustedSignersContextMenu_Opened;
				TrustedSignersGrid.ContextMenu.Opened += TrustedSignersContextMenu_Opened;
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
			LoadTrustedSigners();
		}

		private void ProjectScopeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (!IsLoaded || GetSelectedScope() != TrustScope.Project)
			{
				return;
			}

			hasChanges = false;
			LoadTrustedSigners();
		}

		/// <summary>
		/// Loads all signer-scoped trust entries from the trust store.
		/// </summary>
		private void LoadTrustedSigners()
		{
			trustedSigners.Clear();

			try
			{
				var trustStoreService = new TrustStoreService();
				trustStorePath = ResolveTrustStorePath(trustStoreService, GetSelectedScope(), this.solutionPath, GetSelectedProjectPathForScope());

				if (!System.IO.File.Exists(trustStorePath))
				{
					return;
				}

				var document = trustStoreService.Load(trustStorePath);

				if (document?.Decisions == null || document.Decisions.Count == 0)
				{
					return;
				}

				var signerTrusts = document.Decisions
					.Where(d => d.ScopeKind == TrustDecisionScopeKind.Signer ||
								string.Equals(d.Scope, "Signer", StringComparison.OrdinalIgnoreCase))
					.GroupBy(d => d.SubjectHash, StringComparer.OrdinalIgnoreCase)
					.Select(g =>
					{
						var first = g.OrderByDescending(x => x.CreatedAtUtc).First();

						return new SignerTrustItem
						{
							SubjectDn        = first.SubjectHash,
							SignerName        = first.AssemblySigner,
							Issuer           = first.AssemblyIssuer,
							Reason           = first.Reason,
							CreatedAtDisplay = first.CreatedAtUtc.LocalDateTime.ToString("yyyy-MM-dd HH:mm")
						};
					})
					.OrderBy(s => s.SignerName)
					.ToList();

				foreach (var item in signerTrusts)
				{
					trustedSigners.Add(item);
				}
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

			trustedSigners.Remove(selected);
			hasChanges = true;
			UpdateRemoveButtonState();
		}

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

			MoveTrustToScope(selectedTrust, targetScope, this.projectPath);
		}

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

			MoveTrustToScope(selectedTrust, TrustScope.Project, targetProjectPath);
		}

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

		private void MoveTrustToScope(SignerTrustItem selectedTrust, TrustScope targetScope, string targetProjectPath)
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
				var targetStore = trustStoreService.Load(targetPath);
				var sourceEntries = sourceStore.Decisions
					.Where(d => (d.ScopeKind == TrustDecisionScopeKind.Signer || string.Equals(d.Scope, "Signer", StringComparison.OrdinalIgnoreCase)) && string.Equals(d.SubjectHash, selectedTrust.SubjectDn, StringComparison.OrdinalIgnoreCase))
					.ToList();

				if (sourceEntries.Count == 0)
				{
					return;
				}

				foreach (var sourceEntry in sourceEntries)
				{
					targetStore.Decisions.Add(new TrustDecisionEntry
					{
						DecisionId = Guid.NewGuid().ToString("N"),
						Scope = sourceEntry.Scope,
						SubjectHash = sourceEntry.SubjectHash,
						AssemblySigner = sourceEntry.AssemblySigner,
						AssemblyIssuer = sourceEntry.AssemblyIssuer,
						AssemblySubject = sourceEntry.AssemblySubject,
						AssemblyThumbprint = sourceEntry.AssemblyThumbprint,
						AssemblySerialNumber = sourceEntry.AssemblySerialNumber,
						Decision = sourceEntry.Decision,
						Reason = sourceEntry.Reason,
						UserSid = userSid,
						CreatedAtUtc = DateTimeOffset.UtcNow,
						ExpiresAtUtc = sourceEntry.ExpiresAtUtc,
						RepositoryRemote = sourceEntry.RepositoryRemote,
						Branch = sourceEntry.Branch,
						CommitSha = sourceEntry.CommitSha,
						PolicyProfile = sourceEntry.PolicyProfile
					});
				}

				foreach (var sourceEntry in sourceEntries)
				{
					sourceStore.Decisions.Remove(sourceEntry);
				}

				trustStoreService.Save(sourcePath, sourceStore);
				trustStoreService.Save(targetPath, targetStore);

				trustedSigners.Remove(selectedTrust);
				hasMovedTrust = true;
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
			if (!hasChanges)
			{
				DialogResult = false;
				Close();
				return;
			}

			try
			{
				var trustStoreService = new TrustStoreService();

				if (string.IsNullOrWhiteSpace(trustStorePath))
				{
					trustStorePath = ResolveTrustStorePath(trustStoreService, GetSelectedScope(), this.solutionPath, GetSelectedProjectPathForScope());
				}

				var document = trustStoreService.Load(trustStorePath);

				if (document?.Decisions == null)
				{
					document = new TrustStoreDocument { Decisions = new List<TrustDecisionEntry>() };
				}

				// Remove all existing signer trusts, then re-add the survivors.
				var existingSignerTrusts = document.Decisions
					.Where(d => d.ScopeKind == TrustDecisionScopeKind.Signer ||
								string.Equals(d.Scope, "Signer", StringComparison.OrdinalIgnoreCase))
					.ToList();

				foreach (var entry in existingSignerTrusts)
				{
					document.Decisions.Remove(entry);
				}

				var userSid = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

				foreach (var item in trustedSigners)
				{
					var entry = new TrustDecisionEntry
					{
						DecisionId      = Guid.NewGuid().ToString(),
						Scope           = "Signer",
						SubjectHash     = item.SubjectDn,
						AssemblySigner  = item.SignerName,
						AssemblyIssuer  = item.Issuer,
						AssemblySubject = item.SubjectDn,
						Decision        = "Trust",
						Reason          = item.Reason,
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
				MessageBox.Show($"Error saving signer trusts: {ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
		protected override async void OnClosed(EventArgs e)
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

			await MSBuildGuardPackage.Instance.RescanSolutionSecurityReviewAsync();
		}

		private TrustScope GetSelectedScope()
		{
			return ScopeComboBox?.SelectedItem is TrustScope scope ? scope : TrustScope.User;
		}

		private string GetSelectedProjectPathForScope()
		{
			return ProjectScopeComboBox?.SelectedValue as string ?? this.projectPath;
		}

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
	/// Represents a single trusted signer entry in the list.
	/// </summary>
	internal class SignerTrustItem
	{
		/// <summary>
		/// Gets or sets the certificate Subject DN used as the canonical trust key.
		/// </summary>
		public string SubjectDn { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the human-readable signer display name.
		/// </summary>
		public string SignerName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate issuer.
		/// </summary>
		public string Issuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the reason the signer was trusted.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the formatted trust creation date for display.
		/// </summary>
		public string CreatedAtDisplay { get; set; } = string.Empty;
	}
}
