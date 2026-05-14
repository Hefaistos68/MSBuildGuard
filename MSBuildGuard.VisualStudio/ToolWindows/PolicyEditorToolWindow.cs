using System.Collections.Generic;
using Microsoft.VisualStudio.Shell;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Hosts the Policy Editor content.
	/// </summary>
	public sealed class PolicyEditorToolWindow : ToolWindowPane
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="PolicyEditorToolWindow"/> class.
		/// </summary>
		public PolicyEditorToolWindow()
			: base(null)
		{
			this.Caption = "MSBuild Guard - Policy Editor";
			this.Content = new PolicyEditorControl();
		}

		/// <summary>
		/// Loads policy context into the editor control.
		/// </summary>
		/// <param name="solutionPath">The currently open solution path.</param>
		/// <param name="projectPaths">All loaded project paths available for project-scoped editing.</param>
		/// <param name="preferredPolicyType">Preferred policy scope to select when available.</param>
		internal void LoadPolicyContext(string solutionPath, IReadOnlyList<string> projectPaths, PolicyEditorViewModel.PolicyScopeType? preferredPolicyType)
		{
			if (this.Content is PolicyEditorControl control)
			{
				control.LoadPolicyContext(solutionPath, projectPaths, preferredPolicyType);
			}
		}
	}
}
