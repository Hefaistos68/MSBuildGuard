namespace MSBuildGuard.VisualStudio.Models
{
	/// <summary>
	/// Represents the supported trust storage scope options in Visual Studio dialogs.
	/// </summary>
	public enum TrustScope
	{
		/// <summary>
		/// Persist trust in the current user profile trust store.
		/// </summary>
		User,

		/// <summary>
		/// Persist trust in the current solution trust store.
		/// </summary>
		Solution,

		/// <summary>
		/// Persist trust in the current project trust store.
		/// </summary>
		Project
	}
}
