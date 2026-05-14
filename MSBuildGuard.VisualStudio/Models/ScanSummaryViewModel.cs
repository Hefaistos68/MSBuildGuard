using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using MSBuildGuard.Core.Extensions;
using MSBuildGuard.VisualStudio.Services;


namespace MSBuildGuard.VisualStudio.Models
{
	/// <summary>
	/// Represents summary values for a scan report.
	/// </summary>
	public sealed class ScanSummaryViewModel : INotifyPropertyChanged
	{
		private string targetPath = "No scan loaded";
		private int riskScore;
		private int trustedRiskScore;
		private string recommendedAction = "Unknown";
		private int filesScanned;
		private int findingsCount;
		private bool hasTargetLoaded;

		/// <summary>
		/// Occurs when a property value changes.
		/// </summary>
		public event PropertyChangedEventHandler? PropertyChanged;

		/// <summary>
		/// Gets or sets target path text.
		/// </summary>
		public string TargetPath
		{
			get
			{
				return this.targetPath;
			}
			set
			{
				if (this.SetProperty(ref this.targetPath, value))
				{
					this.OnPropertyChanged(nameof(this.TargetPathDisplay));
					this.OnPropertyChanged(nameof(this.TargetNameDisplay));
				}
			}
		}

		/// <summary>
		/// Gets the target path formatted for compact header display.
		/// </summary>
		public string TargetPathDisplay
		{
			get
			{
				return PathRedactionService.RedactPath(this.TargetPath).TrimMiddlePath(72);
			}
		}

		/// <summary>
		/// Gets the scanned project name for title display.
		/// </summary>
		public string TargetNameDisplay
		{
			get
			{
				if (string.IsNullOrWhiteSpace(this.TargetPath))
				{
					return "No target";
				}

				var fileName = Path.GetFileNameWithoutExtension(this.TargetPath);

				if (string.IsNullOrWhiteSpace(fileName))
				{
					return PathRedactionService.RedactPath(this.TargetPath);
				}

				return fileName;
			}
		}

		/// <summary>
		/// Gets or sets risk score.
		/// </summary>
		public int RiskScore
		{
			get
			{
				return this.riskScore;
			}
			set
			{
				if (this.SetProperty(ref this.riskScore, value))
				{
					this.OnPropertyChanged(nameof(this.RiskIndicator));
					this.OnPropertyChanged(nameof(this.RiskIndicatorBrush));
					this.OnPropertyChanged(nameof(this.RiskScoreDisplay));
				}
			}
		}

		/// <summary>
		/// Gets or sets risk score contributed by trusted findings.
		/// </summary>
		public int TrustedRiskScore
		{
			get
			{
				return this.trustedRiskScore;
			}
			set
			{
				if (this.SetProperty(ref this.trustedRiskScore, value))
				{
					this.OnPropertyChanged(nameof(this.RiskScoreDisplay));
				}
			}
		}

		/// <summary>
		/// Gets the formatted risk score text with trusted-risk contribution.
		/// </summary>
		public string RiskScoreDisplay
		{
			get
			{
				return this.TrustedRiskScore > 0
					? $"{this.RiskScore} (+{this.TrustedRiskScore} trusted)"
					: this.RiskScore.ToString();
			}
		}

		/// <summary>
		/// Gets a glyph indicator representing the current risk level.
		/// </summary>
		public string RiskIndicator
		{
			get
			{
				return "●";
			}
		}
		
		/// <summary>
		/// Gets the brush used to color the risk indicator glyph.
		/// </summary>
		public Brush RiskIndicatorBrush
		{
			get
			{
				if (this.RiskScore >= 100)
				{
					return Brushes.Red;
				}

				if (this.RiskScore >= 20)
				{
					return Brushes.Orange;
				}

				return Brushes.Green;
			}
		}

		/// <summary>
		/// Gets or sets recommended action text.
		/// </summary>
		public string RecommendedAction
		{
			get
			{
				return this.recommendedAction;
			}
			set
			{
				this.SetProperty(ref this.recommendedAction, value);
			}
		}

		/// <summary>
		/// Gets or sets files scanned count.
		/// </summary>
		public int FilesScanned
		{
			get
			{
				return this.filesScanned;
			}
			set
			{
				this.SetProperty(ref this.filesScanned, value);
			}
		}

		/// <summary>
		/// Gets or sets findings count.
		/// </summary>
		public int FindingsCount
		{
			get
			{
				return this.findingsCount;
			}
			set
			{
				this.SetProperty(ref this.findingsCount, value);
			}
		}

		/// <summary>
		/// Gets or sets a value indicating whether a valid target is currently loaded.
		/// </summary>
		public bool HasTargetLoaded
		{
			get
			{
				return this.hasTargetLoaded;
			}
			set
			{
				this.SetProperty(ref this.hasTargetLoaded, value);
			}
		}

		private void OnPropertyChanged([CallerMemberName] string propertyName = "")
		{
			this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		private bool SetProperty<T>(ref T storage, T value, [CallerMemberName] string propertyName = "")
		{
			if (EqualityComparer<T>.Default.Equals(storage, value))
			{
				return false;
			}

			storage = value;
			this.OnPropertyChanged(propertyName);

			return true;
		}
	}
}
