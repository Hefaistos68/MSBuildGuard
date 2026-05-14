using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Windows;
using Microsoft.Win32;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Dialog for managing trusted assemblies.
	/// </summary>
	public partial class ManageAssemblyTrustsDialog : Window
	{
		private ObservableCollection<AssemblyTrustItem> trustedAssemblies = new();
		private string trustStorePath = string.Empty;
		private bool hasChanges = false;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageAssemblyTrustsDialog"/> class.
		/// </summary>
		public ManageAssemblyTrustsDialog()
		{
			InitializeComponent();
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted assemblies.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			LoadTrustedAssemblies();
			TrustedAssembliesGrid.ItemsSource = trustedAssemblies;
			TrustedAssembliesGrid.SelectionChanged += (s, args) => UpdateRemoveButtonState();
		}

		/// <summary>
		/// Loads all trusted assemblies from the trust store.
		/// </summary>
		private void LoadTrustedAssemblies()
		{
			try
			{
				var trustStoreService = new TrustStoreService();
				trustStorePath = trustStoreService.GetDefaultUserTrustPath();

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
					.Select(g => new AssemblyTrustItem
					{
						Name      = ExtractAssemblyName(g.Key),
						Version   = ExtractAssemblyVersion(g.Key),
						Reason    = g.FirstOrDefault()?.Reason ?? string.Empty,
						Subject   = g.Key
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
				AssemblyName    = assemblyName,
				AssemblyVersion = assemblyVersion,
				AssemblyPath    = assemblyPath,
				Owner           = this,
				WindowStartupLocation = WindowStartupLocation.CenterOwner
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
				Name    = assemblyName,
				Version = assemblyVersion,
				Reason  = trustDialog.TrustReason,
				Subject = $"{assemblyName}@{assemblyVersion}"
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
						DecisionId  = Guid.NewGuid().ToString(),
						Scope       = "Assembly",
						SubjectHash = trust.Subject,
						Decision    = "Trust",
						Reason      = trust.Reason,
						UserSid     = userSid,
						CreatedAtUtc = DateTimeOffset.UtcNow
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
	}

	/// <summary>
	/// Represents a single trusted assembly item in the list.
	/// </summary>
	internal class AssemblyTrustItem
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
		/// Gets or sets the trust reason.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the subject identifier (name@version).
		/// </summary>
		public string Subject { get; set; } = string.Empty;
	}
}
