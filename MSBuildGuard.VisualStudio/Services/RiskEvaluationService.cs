using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.ToolWindows;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Evaluates scan reports and determines whether user attention is required.
	/// </summary>
	internal sealed class RiskEvaluationService
	{
		/// <summary>
		/// Determines whether the provided scan report should be surfaced as a warning.
		/// </summary>
		/// <param name="report">The scan report to evaluate.</param>
		/// <returns>A value indicating whether user attention is required.</returns>
		public static bool RequiresUserAttention(ScanReport report)
		{
			if (report == null)
			{
				return false;
			}

			return report.RecommendedAction == RecommendedAction.Warn || report.RecommendedAction == RecommendedAction.RequireApproval || report.RecommendedAction == RecommendedAction.Block;
		}

		/// <summary>
		/// Determines whether the provided trust-aware build-block view model still requires blocking.
		/// </summary>
		/// <param name="viewModel">The trust-aware build-block view model to evaluate.</param>
		/// <returns>A value indicating whether build should be blocked.</returns>
		public static bool RequiresBuildBlock(BuildBlockDialogViewModel viewModel)
		{
			if (viewModel == null)
			{
				return false;
			}

			return viewModel.RiskScore >= 50;
		}

		/// <summary>
		/// Determines whether the provided report should block build execution because policy requires user action.
		/// </summary>
		/// <param name="report">The scan report to evaluate.</param>
		/// <returns>A value indicating whether build should be blocked.</returns>
		public static bool RequiresBuildBlock(ScanReport report)
		{
			if (report == null)
			{
				return false;
			}

			return report.RecommendedAction == RecommendedAction.RequireApproval || report.RecommendedAction == RecommendedAction.Block;
		}
	}
}
