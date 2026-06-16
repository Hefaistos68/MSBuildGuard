using System;
using System.Windows;
using Microsoft.VisualStudio.PlatformUI;
using MSBuildGuard.VisualStudio.Options;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Dialog for configuring key management mode on the first run of the extension.
	/// </summary>
	public partial class KeyManagementOnboardingDialog : DialogWindow
	{
		/// <summary>
		/// Gets the view model.
		/// </summary>
		public KeyManagementOnboardingViewModel ViewModel { get; }

		/// <summary>
		/// Initializes a new instance of the <see cref="KeyManagementOnboardingDialog"/> class.
		/// </summary>
		/// <param name="viewModel">The view model.</param>
		public KeyManagementOnboardingDialog(KeyManagementOnboardingViewModel viewModel)
		{
			this.ViewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
			this.InitializeComponent();

			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
		}

		private void SoloDeveloperButton_Click(object sender, RoutedEventArgs e)
		{
			this.ViewModel.SelectedMode = KeyManagementModeKind.DPAPI;
			this.DialogResult = true;

			this.Close();
		}

		private void TeamEnvironmentButton_Click(object sender, RoutedEventArgs e)
		{
			this.ViewModel.SelectedMode = KeyManagementModeKind.Certificates;
			this.DialogResult = true;

			this.Close();
		}

		private void ConfigureLaterButton_Click(object sender, RoutedEventArgs e)
		{
			this.ViewModel.SelectedMode = KeyManagementModeKind.Unconfigured;
			this.DialogResult = false;

			this.Close();
		}
	}
}
