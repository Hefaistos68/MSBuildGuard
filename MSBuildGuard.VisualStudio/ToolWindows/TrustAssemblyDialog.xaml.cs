using System.Windows;
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
		/// Gets the trust reason text entered by the user.
		/// </summary>
		public string TrustReason { get; private set; } = string.Empty;

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
			AssemblyNameTextBlock.Text = this.AssemblyName;
			AssemblyVersionTextBlock.Text = this.AssemblyVersion;
			AssemblyPathTextBlock.Text = PathRedactionService.RedactPath(this.AssemblyPath);
		}

		/// <summary>
		/// Handles the Trust button click.
		/// </summary>
		private void TrustButton_Click(object sender, RoutedEventArgs e)
		{
			this.TrustReason = this.ReasonTextBox.Text;
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
