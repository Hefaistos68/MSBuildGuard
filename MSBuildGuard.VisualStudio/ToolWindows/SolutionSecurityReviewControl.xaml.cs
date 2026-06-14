using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;
using MSBuildGuard.Core.Trust;

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

			var viewModel = new SolutionSecurityReviewViewModel();

			viewModel.PropertyChanged += this.OnViewModelPropertyChanged;
			this.DataContext = viewModel;
			this.UpdateTrustedColumnVisibility();
		}

		/// <summary>
		/// Handles view model property changes to update column visibility when the filter changes.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Property changed event arguments.</param>
		private void OnViewModelPropertyChanged(object sender, PropertyChangedEventArgs e)
		{
			if (string.Equals(e.PropertyName, nameof(SolutionSecurityReviewViewModel.OnlyUntrustedIssues), StringComparison.Ordinal))
			{
				this.UpdateTrustedColumnVisibility();
			}
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

		/// <summary>
		/// Handles the Edit Policy button click by opening the Policy Editor tool window.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
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

		/// <summary>
		/// Handles the Rescan button click by triggering a full solution rescan.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
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

		/// <summary>
		/// Handles double-click on a findings row by navigating to the finding's source location in the editor.
		/// </summary>
		/// <param name="sender">Event sender (the findings data grid).</param>
		/// <param name="e">Mouse button event arguments.</param>
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

		/// <summary>
		/// Handles the Trust Finding button click by adding a fingerprint-based trust decision.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
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

		/// <summary>
		/// Handles the Remove Trust button click by deleting the trust decision for the selected finding.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
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

		/// <summary>
		/// Handles the Trust Assembly button click by opening the Trust Assembly dialog.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
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

		/// <summary>
		/// Handles the Trust Package button click by opening the Trust Package dialog.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
		private void OnTrustPackageClick(object sender, RoutedEventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				if (this.DataContext is not SolutionSecurityReviewViewModel viewModel ||
					viewModel.SelectedFinding is not FindingViewModel finding ||
					!finding.CanTrustPackage ||
					MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
				{
					return;
				}

				await new VisualStudioTrustDecisionService().TrustPackageAsync(finding, "Trusted from Solution Security Review");
				await package.RescanSolutionSecurityReviewAsync();
			}).FileAndForget(nameof(SolutionSecurityReviewControl));
		}

		/// <summary>
		/// Handles the Assembly Information button click by opening the Assembly Information dialog.
		/// </summary>
		/// <param name="sender">Event sender.</param>
		/// <param name="e">Routed event arguments.</param>
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



		/// <summary>
		/// Applies a descending severity sort to the findings grid collection view.
		/// </summary>
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

		/// <summary>
		/// Toggles visibility of the Trusted column based on the current filter state.
		/// </summary>
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
