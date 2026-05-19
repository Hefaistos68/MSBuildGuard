using System;
using System.ComponentModel;
using System.Drawing.Design;
using Microsoft.VisualStudio.Shell;

namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// UI editor that launches the Manage Signer Trusts dialog from the options page.
	/// </summary>
	public sealed class ManageSignerTrustsEditor : UITypeEditor
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
					await MSBuildGuardPackage.Instance.ShowManageSignerTrustsAsync().ConfigureAwait(false);
				});
			}

			return value ?? string.Empty;
		}
	}
}
