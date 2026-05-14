using System.Windows;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Code-behind for the build block confirmation dialog.
	/// </summary>
	public partial class BuildBlockDialog : Window
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
			this.DataContext = viewModel;
		}

		private void OnProceedClick(object sender, RoutedEventArgs e)
		{
			this.UserChoseToProceed = true;
			this.Close();
		}

		private void OnCancelClick(object sender, RoutedEventArgs e)
		{
			this.UserChoseToProceed = false;
			this.Close();
		}
	}
}
