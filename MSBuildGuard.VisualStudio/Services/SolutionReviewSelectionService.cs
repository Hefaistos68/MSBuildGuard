namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Stores latest review target selections for tool-window initiated rescans.
	/// </summary>
	internal sealed class SolutionReviewSelectionService
	{
		private string? solutionReviewTargetPath;

		/// <summary>
		/// Gets or sets the last loaded Solution Security Review target path.
		/// </summary>
		public string? SolutionReviewTargetPath
		{
			get
			{
				return this.solutionReviewTargetPath;
			}
			set
			{
				this.solutionReviewTargetPath = value;
			}
		}
	}
}
