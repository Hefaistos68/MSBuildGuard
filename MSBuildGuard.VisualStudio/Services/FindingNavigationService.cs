using System;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Microsoft.VisualStudio.TextManager.Interop;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Navigates to finding locations in the editor.
	/// </summary>
	internal sealed class FindingNavigationService
	{
		/// <summary>
		/// Opens a file and moves caret to the requested location.
		/// </summary>
		/// <param name="serviceProvider">Visual Studio service provider.</param>
		/// <param name="filePath">File path.</param>
		/// <param name="line">1-based line number.</param>
		/// <param name="column">1-based column number.</param>
		public static void Navigate(IServiceProvider serviceProvider, string filePath, int line, int column)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (serviceProvider == null)
			{
				throw new ArgumentNullException(nameof(serviceProvider));
			}

			if (string.IsNullOrWhiteSpace(filePath))
			{
				throw new ArgumentException("A file path is required.", nameof(filePath));
			}

			var targetLine   = Math.Max(0, line - 1);
			var targetColumn = Math.Max(0, column - 1);

			VsShellUtilities.OpenDocument(serviceProvider, filePath, Guid.Empty, out _, out _, out var windowFrame);

			if (windowFrame == null)
			{
				return;
			}

			windowFrame.Show();

			if (windowFrame is IVsWindowFrame frame)
			{
				frame.GetProperty((int)__VSFPROPID.VSFPROPID_DocView, out var docView);

				if (docView is IVsTextView textView)
				{
					textView.SetCaretPos(targetLine, targetColumn);
					textView.CenterLines(targetLine, 1);
				}
			}
		}
	}
}
