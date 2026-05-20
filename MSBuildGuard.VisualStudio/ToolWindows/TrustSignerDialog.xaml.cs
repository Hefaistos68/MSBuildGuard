using System;
using System.Collections.Generic;
using System.Windows;
using Microsoft.VisualStudio.PlatformUI;
using MSBuildGuard.VisualStudio.Models;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Confirmation dialog for trusting a signer certificate identity.
	/// </summary>
	public partial class TrustSignerDialog : DialogWindow
	{
		/// <summary>
		/// Gets or sets the signer display name.
		/// </summary>
		public string SignerName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the signer certificate issuer.
		/// </summary>
		public string Issuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the signer certificate subject.
		/// </summary>
		public string Subject { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the signer certificate thumbprint.
		/// </summary>
		public string Thumbprint { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the currently opened solution path.
		/// </summary>
		public string SolutionPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the currently selected project path.
		/// </summary>
		public string ProjectPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets the trust reason entered by the user.
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
		/// Initializes a new instance of the <see cref="TrustSignerDialog"/> class.
		/// </summary>
		public TrustSignerDialog()
		{
			InitializeComponent();
			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
		}

		/// <summary>
		/// Initializes dialog values and scope options.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			SignerNameTextBlock.Text = string.IsNullOrWhiteSpace(this.SignerName) ? "Not available" : this.SignerName;
			IssuerTextBlock.Text     = string.IsNullOrWhiteSpace(this.Issuer) ? "Not available" : this.Issuer;
			SubjectTextBlock.Text    = string.IsNullOrWhiteSpace(this.Subject) ? "Not available" : this.Subject;
			ThumbprintTextBlock.Text = string.IsNullOrWhiteSpace(this.Thumbprint) ? "Not available" : this.Thumbprint;

			this.InitializeScopeOptions();
		}

		/// <summary>
		/// Initializes available scope options based on current context.
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
		/// Handles the expiration toggle checkbox state.
		/// </summary>
		private void NoExpirationCheckBox_Changed(object sender, RoutedEventArgs e)
		{
			if (NoExpirationCheckBox == null || ValidUntilDatePicker == null)
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
		/// Handles the trust action confirmation.
		/// </summary>
		private void TrustButton_Click(object sender, RoutedEventArgs e)
		{
			this.TrustReason   = this.ReasonTextBox.Text;
			this.SelectedScope = ScopeComboBox.SelectedItem is TrustScope scope ? scope : TrustScope.User;

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
		/// Handles dialog cancellation.
		/// </summary>
		private void CancelButton_Click(object sender, RoutedEventArgs e)
		{
			this.DialogResult = false;
			this.Close();
		}
	}
}
