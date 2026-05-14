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
		/// Open review command id.
		/// </summary>
		public const int OpenProjectReviewCommandId = 0x0101;


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
		/// Open project security review from solution explorer context menu command id.
		/// </summary>
		public const int OpenProjectReviewContextCommandId = 0x0106;

		/// <summary>
		/// Open solution security review from solution explorer context menu command id.
		/// </summary>
		public const int OpenSolutionReviewContextCommandId = 0x0107;

		/// <summary>
		/// Project security review tool window id.
		/// </summary>
		public const int ProjectSecurityReviewToolWindowId = 0x0200;

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
