using System;
using System.Windows;
using Microsoft.VisualStudio.PlatformUI;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Interaction logic for BaselineOnboardingDialog.xaml.
	/// </summary>
	public partial class BaselineOnboardingDialog : DialogWindow
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="BaselineOnboardingDialog"/> class.
		/// </summary>
		/// <param name="viewModel">The view model for the onboarding process.</param>
		public BaselineOnboardingDialog(BaselineOnboardingViewModel viewModel)
		{
			this.InitializeComponent();

			this.DataContext = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
		}

		/// <summary>
		/// Gets the underlying view model.
		/// </summary>
		internal BaselineOnboardingViewModel ViewModel => (BaselineOnboardingViewModel)this.DataContext;

		private void ApplyButton_Click(object sender, RoutedEventArgs e)
		{
			this.DialogResult = true;

			this.Close();
		}

		private void SkipButton_Click(object sender, RoutedEventArgs e)
		{
			this.DialogResult = false;

			this.Close();
		}
	}
}
