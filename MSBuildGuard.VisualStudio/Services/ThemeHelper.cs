using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.VisualStudio.PlatformUI;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Helper class to apply native title bar theming based on the current Visual Studio theme.
	/// </summary>
	internal static class ThemeHelper
	{
		[DllImport("dwmapi.dll")]
		private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

		private const int DwmwaUseImmersiveDarkModeBefore20H1 = 19;
		private const int DwmwaUseImmersiveDarkMode = 20;

		/// <summary>
		/// Automatically detects the current Visual Studio theme and applies light or dark title bar
		/// styling using native DWM APIs.
		/// </summary>
		/// <param name="window">The WPF window to apply theming to.</param>
		public static void ApplyTitleBarTheme(Window window)
		{
			if (window == null)
			{
				return;
			}

			// Hook SourceInitialized or apply immediately if handle is already created.
			var helper = new WindowInteropHelper(window);
			var hwnd = helper.Handle;

			if (hwnd == IntPtr.Zero)
			{
				window.SourceInitialized += (s, e) =>
				{
					var handle = new WindowInteropHelper(window).Handle;
					if (handle != IntPtr.Zero)
					{
						ApplyThemeToHandle(handle);
					}
				};
			}
			else
			{
				ApplyThemeToHandle(hwnd);
			}
		}

		private static void ApplyThemeToHandle(IntPtr hwnd)
		{
			try
			{
				// Retrieve the active Visual Studio background color.
				var vsBgColor = VSColorTheme.GetThemedColor(EnvironmentColors.ToolWindowBackgroundColorKey);

				// Calculate perceived brightness (standard formula: R * 0.299 + G * 0.587 + B * 0.114)
				double brightness = (vsBgColor.R * 0.299) + (vsBgColor.G * 0.587) + (vsBgColor.B * 0.114);
				bool isDark = brightness < 128;

				int darkMode = isDark ? 1 : 0;

				// Try modern Windows 10/11 immersive dark mode attribute first (20)
				int result = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref darkMode, sizeof(int));
				if (result != 0)
				{
					// Fallback to pre-20H1 attribute (19)
					_ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeBefore20H1, ref darkMode, sizeof(int));
				}
			}
			catch
			{
				// Fail silently if dwmapi or VSColorTheme APIs are unavailable or fail.
			}
		}
	}
}
