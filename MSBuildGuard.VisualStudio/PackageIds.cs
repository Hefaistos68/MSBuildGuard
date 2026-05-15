namespace MSBuildGuard.VisualStudio
{
	/// <summary>
	/// Defines command and tool window ids.
	/// </summary>
	internal static class PackageIds
	{
		/// <summary>
		/// Scan solution command id.
		/// </summary>
		public const int ScanSolutionCommandId = 0x0100;

		/// <summary>
		/// Trust current project command id.
		/// </summary>
		public const int TrustCurrentProjectCommandId = 0x0102;

		/// <summary>
		/// Edit policy command id.
		/// </summary>
		public const int EditPolicyCommandId = 0x0103;

		/// <summary>
		/// Create baseline command id.
		/// </summary>
		public const int CreateBaselineCommandId = 0x0104;

		/// <summary>
		/// Open solution security review command id.
		/// </summary>
		public const int OpenSolutionReviewCommandId = 0x0105;

		/// <summary>
		/// Open solution security review from solution explorer context menu command id.
		/// </summary>
		public const int OpenSolutionReviewContextCommandId = 0x0107;

		/// <summary>
		/// Manage assembly trusts command id.
		/// </summary>
		public const int ManageAssemblyTrustsCommandId = 0x0108;

		/// <summary>
		/// Manage signer trusts command id.
		/// </summary>
		public const int ManageSignerTrustsCommandId = 0x0109;

		/// <summary>
		/// Policy editor tool window id.
		/// </summary>
		public const int PolicyEditorToolWindowId = 0x0201;

		/// <summary>
		/// Solution security review tool window id.
		/// </summary>
		public const int SolutionSecurityReviewToolWindowId = 0x0202;
	}
}
