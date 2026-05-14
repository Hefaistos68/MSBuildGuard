using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.VisualStudio.Shell;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Injects custom WPF content into the Visual Studio status bar.
	/// </summary>
	internal static class StatusBarInjector
	{
		private const string StatusBarPanelName = "StatusBarPanel";
		private const int StatusBarRetryDelayMilliseconds = 5000;

		private static DockPanel? panel;

		/// <summary>
		/// Injects the specified control into the status bar.
		/// </summary>
		/// <param name="element">The control to inject.</param>
		/// <returns>A task that completes when the control is injected.</returns>
		public static async Task InjectControlAsync(FrameworkElement element)
		{
			if (element == null)
			{
				return;
			}

			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
			await EnsureUiAsync();

			if (panel == null)
			{
				return;
			}

			element.SetValue(DockPanel.DockProperty, Dock.Right);
			panel.Children.Add(element);
		}

		private static async Task EnsureUiAsync()
		{
			while (panel == null)
			{
				panel = FindChild(Application.Current?.MainWindow, StatusBarPanelName) as DockPanel;

				if (panel == null)
				{
					await Task.Delay(StatusBarRetryDelayMilliseconds);
				}
			}
		}

		private static DependencyObject? FindChild(DependencyObject? parent, string childName)
		{
			if (parent == null)
			{
				return null;
			}

			var childrenCount = VisualTreeHelper.GetChildrenCount(parent);

			for (var i = 0; i < childrenCount; i++)
			{
				var child = VisualTreeHelper.GetChild(parent, i);

				if (child is FrameworkElement frameworkElement && frameworkElement.Name == childName)
				{
					return frameworkElement;
				}

				child = FindChild(child, childName);

				if (child != null)
				{
					return child;
				}
			}

			return null;
		}
	}
}
