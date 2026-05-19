using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Hosts the Solution Security Review content.
	/// </summary>
	public sealed class SolutionSecurityReviewToolWindow : ToolWindowPane
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="SolutionSecurityReviewToolWindow"/> class.
		/// </summary>
		public SolutionSecurityReviewToolWindow()
			: base(null)
		{
			this.Caption = "Solution Security Review";
			this.Content = new SolutionSecurityReviewControl();
		}

		/// <summary>
		/// Loads a solution scan report into the content control.
		/// </summary>
		/// <param name="solutionPath">The scanned solution path.</param>
		/// <param name="report">The scan report.</param>
		public void LoadReport(string solutionPath, ScanReport report)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (this.Content is SolutionSecurityReviewControl control)
			{
				control.LoadReport(solutionPath, report);
			}
		}

		/// <summary>
		/// Clears report content.
		/// </summary>
		public void ClearReport()
		{
			if (this.Content is SolutionSecurityReviewControl control)
			{
				control.ClearReport();
			}
		}
	}
}
