using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using MSBuildGuard.Core.Trust;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Dialog for managing trusted certificate signers.
	/// Signers are added via the Assembly Information dialog; this dialog only allows removal.
	/// </summary>
	public partial class ManageSignerTrustsDialog : Window
	{
		private ObservableCollection<SignerTrustItem> trustedSigners = new();
		private string trustStorePath = string.Empty;
		private bool hasChanges = false;

		/// <summary>
		/// Initializes a new instance of the <see cref="ManageSignerTrustsDialog"/> class.
		/// </summary>
		public ManageSignerTrustsDialog()
		{
			InitializeComponent();
		}

		/// <summary>
		/// Called when the dialog loads to populate the list of trusted signers.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			LoadTrustedSigners();
			TrustedSignersGrid.ItemsSource = trustedSigners;
			TrustedSignersGrid.SelectionChanged += (s, args) => UpdateRemoveButtonState();
		}

		/// <summary>
		/// Loads all signer-scoped trust entries from the trust store.
		/// </summary>
		private void LoadTrustedSigners()
		{
			try
			{
				var trustStoreService = new TrustStoreService();
				trustStorePath = trustStoreService.GetDefaultUserTrustPath();

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
					trustStorePath = trustStoreService.GetDefaultUserTrustPath();
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
