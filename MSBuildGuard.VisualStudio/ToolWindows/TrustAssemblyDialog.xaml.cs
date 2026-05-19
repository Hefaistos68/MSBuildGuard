using System;
using System.Collections.Generic;
using System.Windows;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Confirmation dialog for trusting an assembly.
	/// </summary>
	public partial class TrustAssemblyDialog : Window
	{
		/// <summary>
		/// Gets or sets the assembly name.
		/// </summary>
		public string AssemblyName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly version.
		/// </summary>
		public string AssemblyVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly path.
		/// </summary>
		public string AssemblyPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly signer display name.
		/// </summary>
		public string AssemblySigner { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly certificate issuer.
		/// </summary>
		public string AssemblyIssuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly certificate subject.
		/// </summary>
		public string AssemblySubject { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the currently opened solution path.
		/// </summary>
		public string SolutionPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the currently selected project path.
		/// </summary>
		public string ProjectPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets the trust reason text entered by the user.
		/// </summary>
		public string TrustReason { get; private set; } = string.Empty;

		/// <summary>
		/// Gets the selected trust scope.
		/// </summary>
		public TrustScope SelectedScope { get; private set; } = TrustScope.User;

		/// <summary>
		/// Gets the optional trust expiration date.
		/// </summary>
		public DateTimeOffset? ExpiresAtUtc { get; private set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="TrustAssemblyDialog"/> class.
		/// </summary>
		public TrustAssemblyDialog()
		{
			InitializeComponent();
		}

		/// <summary>
		/// Called when the dialog loads to populate the UI with assembly details.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			AssemblyNameTextBlock.Text    = this.AssemblyName;
			AssemblyVersionTextBlock.Text = this.AssemblyVersion;
			AssemblyPathTextBlock.Text    = PathRedactionService.RedactPath(this.AssemblyPath);

			var signature = new AssemblySignatureService().ReadSignature(this.AssemblyPath);

			if (string.IsNullOrWhiteSpace(this.AssemblySigner) && string.IsNullOrWhiteSpace(this.AssemblyIssuer) && string.IsNullOrWhiteSpace(this.AssemblySubject))
			{
				this.AssemblySigner  = signature.Signer;
				this.AssemblyIssuer  = signature.Issuer;
				this.AssemblySubject = signature.Subject;
			}

			AssemblySignerTextBlock.Text = signature.HasEmbeddedSignature ? (string.IsNullOrWhiteSpace(this.AssemblySigner) ? "Not available" : this.AssemblySigner) : "No embedded signature";
			AssemblyIssuerTextBlock.Text = signature.HasEmbeddedSignature ? (string.IsNullOrWhiteSpace(this.AssemblyIssuer) ? "Not available" : this.AssemblyIssuer) : "Not available";
			AssemblySubjectTextBlock.Text = signature.HasEmbeddedSignature ? (string.IsNullOrWhiteSpace(this.AssemblySubject) ? "Not available" : this.AssemblySubject) : "Not available";

			this.InitializeScopeOptions();
			TrustButton.IsEnabled = signature.IsSignatureValid;
		}

		/// <summary>
		/// Handles scope availability and default selection.
		/// </summary>
		private void InitializeScopeOptions()
		{
			var items = new List<TrustScope> { TrustScope.User };

			if (!string.IsNullOrWhiteSpace(this.SolutionPath))
			{
				items.Add(TrustScope.Solution);
			}

			if (!string.IsNullOrWhiteSpace(this.ProjectPath))
			{
				items.Add(TrustScope.Project);
			}

			ScopeComboBox.ItemsSource = items;
			ScopeComboBox.SelectedItem = TrustScope.User;
		}

		/// <summary>
		/// Handles the trust expiration toggle state.
		/// </summary>
		private void NoExpirationCheckBox_Changed(object sender, RoutedEventArgs e)
		{
			if (ValidUntilDatePicker == null || NoExpirationCheckBox == null)
			{
				return;
			}

			var noExpiration = NoExpirationCheckBox.IsChecked == true;
			ValidUntilDatePicker.IsEnabled = !noExpiration;

			if (noExpiration)
			{
				ValidUntilDatePicker.SelectedDate = null;
			}
		}

		/// <summary>
		/// Handles the Trust button click.
		/// </summary>
		private void TrustButton_Click(object sender, RoutedEventArgs e)
		{
			this.TrustReason = this.ReasonTextBox.Text;
			this.SelectedScope = ScopeComboBox.SelectedItem is TrustScope trustScope ? trustScope : TrustScope.User;

			if (NoExpirationCheckBox.IsChecked == true || !ValidUntilDatePicker.SelectedDate.HasValue)
			{
				this.ExpiresAtUtc = null;
			}
			else
			{
				this.ExpiresAtUtc = new DateTimeOffset(ValidUntilDatePicker.SelectedDate.Value.Date.AddDays(1).AddTicks(-1), TimeZoneInfo.Local.GetUtcOffset(DateTime.Now)).ToUniversalTime();
			}

			this.DialogResult = true;
			this.Close();
		}

		/// <summary>
		/// Handles the Cancel button click.
		/// </summary>
		private void CancelButton_Click(object sender, RoutedEventArgs e)
		{
			this.DialogResult = false;
			this.Close();
		}
	}
}
