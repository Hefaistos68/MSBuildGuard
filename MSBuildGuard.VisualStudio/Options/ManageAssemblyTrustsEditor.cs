using System;
using System.ComponentModel;
using System.Drawing.Design;
using Microsoft.VisualStudio.Shell;

namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// UI editor that launches the Manage Assembly Trusts dialog from the options page.
	/// </summary>
	public sealed class ManageAssemblyTrustsEditor : UITypeEditor
	{
		/// <inheritdoc/>
		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.Modal;
		}

		/// <inheritdoc/>
		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			if (MSBuildGuardPackage.Instance != null)
			{
				ThreadHelper.JoinableTaskFactory.Run(async delegate
				{
					await MSBuildGuardPackage.Instance.ShowManageAssemblyTrustsAsync().ConfigureAwait(false);
				});
			}

			return value ?? string.Empty;
		}
	}
}
