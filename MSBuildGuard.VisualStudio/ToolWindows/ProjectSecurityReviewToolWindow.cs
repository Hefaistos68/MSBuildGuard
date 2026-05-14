using System;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Hosts the Project Security Review content.
	/// </summary>
	public sealed class ProjectSecurityReviewToolWindow : ToolWindowPane
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="ProjectSecurityReviewToolWindow"/> class.
		/// </summary>
		public ProjectSecurityReviewToolWindow()
			: base(null)
		{
			this.Caption = "Project Security Review";
			this.Content = new ProjectSecurityReviewControl();
		}

		/// <summary>
		/// Loads a scan report into the content control.
		/// </summary>
		/// <param name="projectPath">The scanned project path.</param>
		/// <param name="report">The scan report.</param>
		public void LoadReport(string projectPath, ScanReport report)
		{
			if (this.Content is ProjectSecurityReviewControl control)
			{
				control.LoadReport(projectPath, report);
			}
		}

		/// <summary>
		/// Clears report content.
		/// </summary>
		public void ClearReport()
		{
			if (this.Content is ProjectSecurityReviewControl control)
			{
				control.ClearReport();
			}
		}
	}
}
