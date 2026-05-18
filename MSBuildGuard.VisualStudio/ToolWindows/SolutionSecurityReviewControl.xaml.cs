using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Interaction logic for solution security review control.
	/// </summary>
	public partial class SolutionSecurityReviewControl : UserControl
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="SolutionSecurityReviewControl"/> class.
		/// </summary>
		public SolutionSecurityReviewControl()
		{
			this.InitializeComponent();
			this.DataContext = new SolutionSecurityReviewViewModel();
			this.UpdateTrustedColumnVisibility();
		}

		/// <summary>
		/// Loads the provided scan report into the control.
		/// </summary>
		/// <param name="solutionPath">The scanned solution path.</param>
		/// <param name="report">The scan report.</param>
		public void LoadReport(string solutionPath, ScanReport report)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (this.DataContext is SolutionSecurityReviewViewModel viewModel)
			{
				var loadedProjectPaths = SolutionExplorerProjectDiscoveryService.GetLoadedProjectPaths();
				viewModel.LoadReport(solutionPath, report, loadedProjectPaths);
				this.ApplyDefaultSeveritySort();
				this.UpdateTrustedColumnVisibility();

				if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
				{
					_ = package.UiFeedbackService.WriteLineAsync($"[Flow] SolutionSecurityReviewControl.LoadReport target='{solutionPath}', findings={report.Findings.Count}, loadedProjects={loadedProjectPaths.Count}", package.DisposalToken);
				}
			}
		}

		/// <summary>
		/// Clears the current report and disables action buttons.
		/// </summary>
		public void ClearReport()
		{
			if (this.DataContext is SolutionSecurityReviewViewModel viewModel)
			{
				viewModel.LoadEmpty();
				this.UpdateTrustedColumnVisibility();
			}
		}

		private void OnEditPolicyClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
				{
					await package.ShowPolicyEditorAsync(PolicyEditorViewModel.PolicyScopeType.Solution);
				}
			}).FileAndForget(nameof(SolutionSecurityReviewControl));
		}

		private void OnRescanClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
				{
					await package.RescanSolutionSecurityReviewAsync();
				}
			}).FileAndForget(nameof(SolutionSecurityReviewControl));
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
				if (this.DataContext is not SolutionSecurityReviewViewModel viewModel ||
					viewModel.SelectedFinding is not FindingViewModel finding ||
					!finding.CanTrust ||
					MSBuildGuardPackage.Instance is not MSBuildGuardPackage package ||
					package.LatestScanReport == null)
				{
					return;
				}

				new VisualStudioTrustDecisionService().TrustUntilChanged(package.LatestScanReport, finding, "Trusted from Solution Security Review");
				await package.OnPolicyChangedRescanAsync();
			}).FileAndForget(nameof(SolutionSecurityReviewControl));
		}

		private void OnRemoveTrustFindingClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (this.DataContext is not SolutionSecurityReviewViewModel viewModel ||
					viewModel.SelectedFinding is not FindingViewModel finding ||
					!finding.CanRemoveTrust ||
					MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
				{
					return;
				}

				new VisualStudioTrustDecisionService().RemoveTrust(finding, "Trust removed from Solution Security Review");
				await package.OnPolicyChangedRescanAsync();
			}).FileAndForget(nameof(SolutionSecurityReviewControl));
		}

		private void OnTrustAssemblyClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (this.DataContext is not SolutionSecurityReviewViewModel viewModel ||
					viewModel.SelectedFinding is not FindingViewModel finding ||
					!finding.CanTrustAssembly ||
					MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
				{
					return;
				}

				await new VisualStudioTrustDecisionService().TrustAssemblyAsync(finding, "Trusted from Solution Security Review");
				await package.RescanSolutionSecurityReviewAsync();
			}).FileAndForget(nameof(SolutionSecurityReviewControl));
		}

		private void OnAssemblyInformationClick(object sender, RoutedEventArgs e)
		{
			if (this.DataContext is not SolutionSecurityReviewViewModel viewModel ||
				viewModel.SelectedFinding is not FindingViewModel finding ||
				!finding.CanTrustAssembly)
			{
				return;
			}

			var parts = finding.OwningAssembly.Split('@');
			var assemblyPath = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion)
				? AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion)
				: AssemblySignatureService.ResolveAssemblyFilePath(finding.FilePath);

			var dialog = new AssemblyInformationDialog
			{
				AssemblyName    = parts[0],
				AssemblyVersion = parts.Length > 1 ? parts[1] : "Unknown",
				AssemblyPath    = assemblyPath,
				Owner           = System.Windows.Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner
			};

			dialog.ShowDialog();
		}

		private void OnOnlyUntrustedIssuesCheckedChanged(object sender, RoutedEventArgs e)
		{
			this.UpdateTrustedColumnVisibility();
		}

		private void ApplyDefaultSeveritySort()
		{
			var view = CollectionViewSource.GetDefaultView(this.FindingsGrid.ItemsSource);

			if (view == null)
			{
				return;
			}

			using (view.DeferRefresh())
			{
				view.SortDescriptions.Clear();
				view.SortDescriptions.Add(new SortDescription(nameof(FindingViewModel.SeveritySortRank), ListSortDirection.Descending));
			}
		}

		private void UpdateTrustedColumnVisibility()
		{
			if (this.DataContext is not SolutionSecurityReviewViewModel viewModel)
			{
				return;
			}

			TrustedColumn.Visibility = viewModel.OnlyUntrustedIssues ? Visibility.Collapsed : Visibility.Visible;
		}
	}
}
