using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.VisualStudio.PlatformUI;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;
using MSBuildGuard.Core.Trust;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Confirmation dialog for trusting a NuGet package by directory hash.
	/// </summary>
	public partial class TrustPackageDialog : DialogWindow
	{
		/// <summary>
		/// Gets or sets the package identifier.
		/// </summary>
		public string PackageId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package version.
		/// </summary>
		public string PackageVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the package directory path.
		/// </summary>
		public string PackagePath { get; set; } = string.Empty;

		/// <summary>
		/// Gets the calculated directory hash.
		/// </summary>
		public string PackageHash { get; private set; } = string.Empty;

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

		private readonly List<SolutionProjectOptionViewModel> projectOptions = new List<SolutionProjectOptionViewModel>();

		/// <summary>
		/// Gets the selected project path.
		/// </summary>
		public string SelectedProjectPath { get; private set; } = string.Empty;

		/// <summary>
		/// Initializes a new instance of the <see cref="TrustPackageDialog"/> class.
		/// </summary>
		public TrustPackageDialog()
		{
			InitializeComponent();
			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
		}

		/// <summary>
		/// Called when the dialog loads to compute the directory hash and populate details.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			Microsoft.VisualStudio.Shell.ThreadHelper.ThrowIfNotOnUIThread();

			PackageIdTextBlock.Text      = this.PackageId;
			PackageVersionTextBlock.Text = this.PackageVersion;
			PackagePathTextBlock.Text    = PathRedactionService.RedactPath(this.PackagePath);

			var hash = TrustStoreService.CalculatePackageDirectoryHash(this.PackagePath);

			if (string.IsNullOrWhiteSpace(hash))
			{
				PackageHashTextBlock.Text = "Unable to compute package folder hash.";

				return;
			}

			this.PackageHash = hash;
			PackageHashTextBlock.Text = hash;

			this.InitializeScopeOptions();

			TrustButton.IsEnabled = !string.IsNullOrWhiteSpace(this.PackageId) &&
				!string.IsNullOrWhiteSpace(this.PackageVersion) &&
				!string.IsNullOrWhiteSpace(this.PackagePath) &&
				Directory.Exists(this.PackagePath) &&
				!string.IsNullOrWhiteSpace(this.PackageHash);
		}

		/// <summary>
		/// Handles scope availability and default selection.
		/// </summary>
		private void InitializeScopeOptions()
		{
			Microsoft.VisualStudio.Shell.ThreadHelper.ThrowIfNotOnUIThread();

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

			// Populate projects
			this.projectOptions.Clear();

			if (!string.IsNullOrWhiteSpace(this.SolutionPath))
			{
				try
				{
					var loadedPaths = SolutionExplorerProjectDiscoveryService.GetLoadedProjectPaths();

					foreach (var loadedPath in loadedPaths.Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.OrdinalIgnoreCase))
					{
						this.projectOptions.Add(new SolutionProjectOptionViewModel
						{
							Name = Path.GetFileNameWithoutExtension(loadedPath),
							Path = loadedPath
						});
					}
				}
				catch
				{
					// Keep project selector empty when project discovery is unavailable.
				}
			}

			ProjectComboBox.ItemsSource = this.projectOptions;

			if (this.projectOptions.Count > 0)
			{
				var matched = this.projectOptions.FirstOrDefault(p => string.Equals(p.Path, this.ProjectPath, StringComparison.OrdinalIgnoreCase));

				if (matched != null)
				{
					ProjectComboBox.SelectedItem = matched;
				}
				else
				{
					ProjectComboBox.SelectedIndex = 0;
				}
			}
		}

		/// <summary>
		/// Handles scope selection change to show/hide project selector.
		/// </summary>
		private void ScopeComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
		{
			if (!IsLoaded || ProjectSelectorPanel == null)
			{

				return;
			}

			var selectedScope = ScopeComboBox.SelectedItem is TrustScope scope ? scope : TrustScope.User;

			ProjectSelectorPanel.Visibility = selectedScope == TrustScope.Project ? Visibility.Visible : Visibility.Collapsed;
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

			if (this.SelectedScope == TrustScope.Project)
			{
				this.SelectedProjectPath = ProjectComboBox.SelectedValue as string ?? this.ProjectPath;
			}
			else
			{
				this.SelectedProjectPath = string.Empty;
			}

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
