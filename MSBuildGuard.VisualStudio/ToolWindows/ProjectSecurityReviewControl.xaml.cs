using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Interaction logic for project security review control.
	/// </summary>
	public partial class ProjectSecurityReviewControl : UserControl
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="ProjectSecurityReviewControl"/> class.
		/// </summary>
		public ProjectSecurityReviewControl()
		{
			this.InitializeComponent();
			this.DataContext = new ProjectSecurityReviewViewModel();
		}

		/// <summary>
		/// Loads the provided scan report into the control.
		/// </summary>
		/// <param name="projectPath">The scanned project path.</param>
		/// <param name="report">The scan report.</param>
		public void LoadReport(string projectPath, ScanReport report)
		{
			if (this.DataContext is ProjectSecurityReviewViewModel viewModel)
			{
				viewModel.LoadReport(projectPath, report);
				this.DataContext = null;
				this.DataContext = viewModel;
			}
		}

		/// <summary>
		/// Clears the current report and disables action buttons.
		/// </summary>
		public void ClearReport()
		{
			if (this.DataContext is ProjectSecurityReviewViewModel viewModel)
			{
				viewModel.LoadEmpty();
				this.DataContext = null;
				this.DataContext = viewModel;
			}
		}

		private void OnEditPolicyClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
				{
					await package.ShowPolicyEditorAsync(PolicyEditorViewModel.PolicyScopeType.Project);
				}
			}).FileAndForget(nameof(ProjectSecurityReviewControl));
		}

		private void OnRescanClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
				{
					await package.RescanProjectSecurityReviewAsync();
				}
			}).FileAndForget(nameof(ProjectSecurityReviewControl));
		}

		private void OnFindingsMouseDoubleClick(object sender, MouseButtonEventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (sender is not DataGrid grid)
			{
				return;
			}

			if (grid.SelectedItem is not FindingViewModel finding)
			{
				return;
			}

			if (MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
			{
				return;
			}

			FindingNavigationService.Navigate(package, finding.FilePath, finding.Line, 1);
		}

		private void OnTrustFindingClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (this.DataContext is not ProjectSecurityReviewViewModel viewModel ||
					viewModel.SelectedFinding is not FindingViewModel finding ||
					!finding.CanTrust ||
					MSBuildGuardPackage.Instance is not MSBuildGuardPackage package ||
					package.LatestScanReport == null)
				{
					return;
				}

				new VisualStudioTrustDecisionService().TrustUntilChanged(package.LatestScanReport, finding, "Trusted from Project Security Review");
				await package.OnPolicyChangedRescanAsync();
			}).FileAndForget(nameof(ProjectSecurityReviewControl));
		}

		private void OnRemoveTrustFindingClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (this.DataContext is not ProjectSecurityReviewViewModel viewModel ||
					viewModel.SelectedFinding is not FindingViewModel finding ||
					!finding.CanRemoveTrust ||
					MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
				{
					return;
				}

				new VisualStudioTrustDecisionService().RemoveTrust(finding, "Trust removed from Project Security Review");
				await package.OnPolicyChangedRescanAsync();
			}).FileAndForget(nameof(ProjectSecurityReviewControl));
		}
	}
}
