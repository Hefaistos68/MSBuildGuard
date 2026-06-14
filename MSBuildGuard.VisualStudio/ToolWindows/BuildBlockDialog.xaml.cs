using System.Windows;
using Microsoft.VisualStudio.PlatformUI;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Code-behind for the build block confirmation dialog.
	/// </summary>
	public partial class BuildBlockDialog : DialogWindow
	{
		/// <summary>
		/// Gets a value indicating whether the user chose to proceed despite the block.
		/// </summary>
		public bool UserChoseToProceed { get; private set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="BuildBlockDialog"/> class.
		/// </summary>
		/// <param name="viewModel">The view model providing scan data for the dialog.</param>
		public BuildBlockDialog(BuildBlockDialogViewModel viewModel)
		{
			this.InitializeComponent();
			MSBuildGuard.VisualStudio.Services.ThemeHelper.ApplyTitleBarTheme(this);
			this.DataContext = viewModel;
		}

		/// <summary>
		/// Handles the Proceed button click by setting <see cref="UserChoseToProceed"/> and closing the dialog.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
		private void OnProceedClick(object sender, RoutedEventArgs e)
		{
			this.UserChoseToProceed = true;
			this.Close();
		}

		/// <summary>
		/// Handles the Cancel button click by keeping <see cref="UserChoseToProceed"/> as <c>false</c> and closing the dialog.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
		private void OnCancelClick(object sender, RoutedEventArgs e)
		{
			this.UserChoseToProceed = false;
			this.Close();
		}
	}
}
