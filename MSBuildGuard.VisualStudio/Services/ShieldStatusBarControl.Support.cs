namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Represents the current security level for the shield status control.
	/// </summary>
	internal enum SecurityLevel
	{
		/// <summary>
		/// No findings require user attention.
		/// </summary>
		Green,

		/// <summary>
		/// Findings require user attention but do not block builds.
		/// </summary>
		Orange,

		/// <summary>
		/// Findings block build execution until resolved.
		/// </summary>
		Red
	}
}
