using MSBuildGuard.VisualStudio.Options;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// View model for the key management onboarding dialog.
	/// </summary>
	public sealed class KeyManagementOnboardingViewModel
	{
		/// <summary>
		/// Gets or sets the selected key management mode.
		/// </summary>
		public KeyManagementModeKind SelectedMode { get; set; } = KeyManagementModeKind.Unconfigured;
	}
}
