using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.VisualStudio.Imaging;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Displays the current security level in the Visual Studio status bar.
	/// </summary>
	internal sealed class ShieldStatusBarControl : Border
	{
		private readonly CrispImage shieldImage;
		private readonly TextBlock severityText;
		private readonly MSBuildGuardPackage package;

		/// <summary>
		/// Initializes a new instance of the <see cref="ShieldStatusBarControl"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		public ShieldStatusBarControl(MSBuildGuardPackage package)
		{
			this.package = package;

			this.Margin = new Thickness(2, 0, 6, 0);
			this.Padding = new Thickness(4, 0, 6, 0);
			this.CornerRadius = new CornerRadius(3);
			this.VerticalAlignment = VerticalAlignment.Center;
			this.HorizontalAlignment = HorizontalAlignment.Right;
			this.Background = Brushes.Transparent;
			this.Cursor = Cursors.Hand;
			this.ToolTip = "Open Project Security Review";
			this.MinWidth = 50;

			var panel = new StackPanel
			{
				Orientation = Orientation.Horizontal,
				VerticalAlignment = VerticalAlignment.Center,
				HorizontalAlignment = HorizontalAlignment.Right
			};

			this.shieldImage = new CrispImage
			{
				Width = 16,
				Height = 16,
				Margin = new Thickness(0, 0, 4, 0),
				VerticalAlignment = VerticalAlignment.Center,
				Moniker = KnownMonikers.UACShield
			};

			this.severityText = new TextBlock
			{
				VerticalAlignment = VerticalAlignment.Center,
				Foreground = Brushes.White,
				Text = "Security"
			};

			panel.Children.Add(this.shieldImage);
			panel.Children.Add(this.severityText);
			this.Child = panel;

			this.MouseLeftButtonUp += this.OnMouseLeftButtonUp;
		}

		/// <summary>
		/// Updates the displayed shield state.
		/// </summary>
		/// <param name="report">The current scan report.</param>
		/// <param name="effectiveRiskScore">Optional trust-adjusted risk score from the security review.</param>
		public void UpdateState(ScanReport? report, int? effectiveRiskScore = null)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			var hasOpenSolution = SolutionDiscoveryService.HasOpenSolution();
			this.IsEnabled = hasOpenSolution;
			this.Opacity = hasOpenSolution ? 1.0 : 0.5;

			var level = GetSecurityLevel(report, effectiveRiskScore);

			this.severityText.Text = level switch
			{
				SecurityLevel.Red => "Critical",
				SecurityLevel.Orange => "Warning",
				_ => "Safe"
			};

			this.Background = level switch
			{
				SecurityLevel.Red => new SolidColorBrush(Color.FromRgb(0x9B, 0x1C, 0x1C)) { Opacity = 0.85 },
				SecurityLevel.Orange => new SolidColorBrush(Color.FromRgb(0xCC, 0x7A, 0x00)) { Opacity = 0.85 },
				_ => new SolidColorBrush(Color.FromRgb(0x1F, 0x7A, 0x1F)) { Opacity = 0.85 }
			};
		}

		private static SecurityLevel GetSecurityLevel(ScanReport? report, int? effectiveRiskScore)
		{
			if (effectiveRiskScore.HasValue)
			{
				if (effectiveRiskScore.Value >= 100)
				{
					return SecurityLevel.Red;
				}

				if (effectiveRiskScore.Value >= 20)
				{
					return SecurityLevel.Orange;
				}

				return SecurityLevel.Green;
			}

			return GetSecurityLevel(report);
		}

		private static SecurityLevel GetSecurityLevel(ScanReport? report)
		{
			if (report == null)
			{
				return SecurityLevel.Green;
			}

			if (report.RecommendedAction == RecommendedAction.Block)
			{
				return SecurityLevel.Red;
			}

			if (report.RecommendedAction == RecommendedAction.Warn || report.RecommendedAction == RecommendedAction.RequireApproval)
			{
				return SecurityLevel.Orange;
			}

			return SecurityLevel.Green;
		}

		private void OnMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			this.package.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.package.ShowSolutionSecurityReviewAsync(null, this.package.LatestScanReport);
			}).FileAndForget(nameof(ShieldStatusBarControl));
		}
	}
}
