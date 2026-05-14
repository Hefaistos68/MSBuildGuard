using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Policy;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// View model for the policy editor tool window.
	/// </summary>
	internal sealed class PolicyEditorViewModel : INotifyPropertyChanged
	{
		/// <summary>
		/// Defines policy scope options for editing.
		/// </summary>
		public enum PolicyScopeType
		{
			Machine,
			Solution,
			Project
		}

		private string policyPath = string.Empty;
		private string mode = "warn";
		private bool baselineRequired;
		private readonly ObservableCollection<SolutionProjectOptionViewModel> availableProjects = new ObservableCollection<SolutionProjectOptionViewModel>();
		private SolutionProjectOptionViewModel? selectedProject;
		private bool strictMode;
		private PolicyAction incompleteAnalysisAction = PolicyAction.Warn;
		private PolicyAction unapprovedPackageSourceAction = PolicyAction.RequireApproval;
		private PolicyAction infoAction    = PolicyAction.Allow;
		private PolicyAction lowAction     = PolicyAction.Warn;
		private PolicyAction mediumAction  = PolicyAction.RequireApproval;
		private PolicyAction highAction    = PolicyAction.Block;
		private PolicyAction criticalAction = PolicyAction.Block;
		private string statusMessage = string.Empty;
		private bool isDirty;
		private string policyTypeLabel = "Solution";
		private PolicyScopeType policyType = PolicyScopeType.Solution;
		private string solutionPath = string.Empty;
		private IReadOnlyList<string> projectPaths = Array.Empty<string>();
		private PolicyDocument? loadedDocument;
		private readonly ObservableCollection<PolicyScopeType> availablePolicyTypes = new ObservableCollection<PolicyScopeType>();

		/// <inheritdoc />
		public event PropertyChangedEventHandler? PropertyChanged;

		/// <summary>
		/// Gets the available policy mode values.
		/// </summary>
		public IReadOnlyList<string> AvailableModes { get; } = new[] { "warn", "block" };

		/// <summary>
		/// Gets available policy scope options for the current context.
		/// </summary>
		public IReadOnlyList<PolicyScopeType> AvailablePolicyTypes
		{
			get
			{
				return this.availablePolicyTypes;
			}
		}

		/// <summary>
		/// Gets the available project options when editing project-scoped policy.
		/// </summary>
		public IReadOnlyList<SolutionProjectOptionViewModel> AvailableProjects
		{
			get => this.availableProjects;
		}

		/// <summary>
		/// Gets or sets the selected project for project-scoped policy editing.
		/// </summary>
		public SolutionProjectOptionViewModel? SelectedProject
		{
			get => this.selectedProject;
			set
			{
				if (this.Set(ref this.selectedProject, value))
				{
					this.UpdatePolicyPathFromType();
					this.LoadFromCurrentPolicyType();
				}
			}
		}

		/// <summary>
		/// Gets or sets a value indicating whether the project dropdown is visible.
		/// </summary>
		public bool IsProjectDropdownVisible => this.policyType == PolicyScopeType.Project;

		/// <summary>
		/// Gets the available policy action values.
		/// </summary>
		public IReadOnlyList<PolicyAction> AvailableActions { get; } = new[]
		{
			PolicyAction.Allow,
			PolicyAction.Warn,
			PolicyAction.RequireApproval,
			PolicyAction.Block
		};

		/// <summary>
		/// Gets or sets the path of the loaded policy file.
		/// </summary>
		public string PolicyPath
		{
			get => this.policyPath;
			set
			{
				if (this.Set(ref this.policyPath, value))
				{
					this.OnPropertyChanged(nameof(this.PolicyPathDisplay));
				}
			}
		}

		/// <summary>
		/// Gets the redacted policy path for UI display.
		/// </summary>
		public string PolicyPathDisplay
		{
			get
			{
				return PathRedactionService.RedactPath(this.policyPath);
			}
		}

		/// <summary>
		/// Gets or sets the selected policy type.
		/// </summary>
		public PolicyScopeType PolicyType
		{
			get => this.policyType;
			set
			{
				if (!this.availablePolicyTypes.Contains(value))
				{
					return;
				}

				if (this.Set(ref this.policyType, value))
				{
					this.UpdatePolicyPathFromType();
					this.LoadFromCurrentPolicyType();
				}
			}
		}

		/// <summary>
		/// Gets or sets the current policy type label shown in header.
		/// </summary>
		public string PolicyTypeLabel
		{
			get => this.policyTypeLabel;
			set => this.Set(ref this.policyTypeLabel, value);
		}

		/// <summary>
		/// Gets or sets the policy mode (warn / block).
		/// </summary>
		public string Mode
		{
			get => this.mode;
			set => this.SetDirty(ref this.mode, value);
		}

		/// <summary>
		/// Gets or sets a value indicating whether a baseline is required.
		/// </summary>
		public bool BaselineRequired
		{
			get => this.baselineRequired;
			set => this.SetDirty(ref this.baselineRequired, value);
		}

		/// <summary>
		/// Gets or sets a value indicating whether strict mode is enabled.
		/// </summary>
		public bool StrictMode
		{
			get => this.strictMode;
			set => this.SetDirty(ref this.strictMode, value);
		}

		/// <summary>
		/// Gets or sets the action taken when analysis is incomplete.
		/// </summary>
		public PolicyAction IncompleteAnalysisAction
		{
			get => this.incompleteAnalysisAction;
			set => this.SetDirty(ref this.incompleteAnalysisAction, value);
		}

		/// <summary>
		/// Gets or sets the action taken for unapproved package sources.
		/// </summary>
		public PolicyAction UnapprovedPackageSourceAction
		{
			get => this.unapprovedPackageSourceAction;
			set => this.SetDirty(ref this.unapprovedPackageSourceAction, value);
		}

		/// <summary>
		/// Gets or sets the minimum action for Info severity findings.
		/// </summary>
		public PolicyAction InfoAction
		{
			get => this.infoAction;
			set => this.SetDirty(ref this.infoAction, value);
		}

		/// <summary>
		/// Gets or sets the minimum action for Low severity findings.
		/// </summary>
		public PolicyAction LowAction
		{
			get => this.lowAction;
			set => this.SetDirty(ref this.lowAction, value);
		}

		/// <summary>
		/// Gets or sets the minimum action for Medium severity findings.
		/// </summary>
		public PolicyAction MediumAction
		{
			get => this.mediumAction;
			set => this.SetDirty(ref this.mediumAction, value);
		}

		/// <summary>
		/// Gets or sets the minimum action for High severity findings.
		/// </summary>
		public PolicyAction HighAction
		{
			get => this.highAction;
			set => this.SetDirty(ref this.highAction, value);
		}

		/// <summary>
		/// Gets or sets the minimum action for Critical severity findings.
		/// </summary>
		public PolicyAction CriticalAction
		{
			get => this.criticalAction;
			set => this.SetDirty(ref this.criticalAction, value);
		}

		/// <summary>
		/// Gets or sets the status message shown to the user.
		/// </summary>
		public string StatusMessage
		{
			get => this.statusMessage;
			set => this.Set(ref this.statusMessage, value);
		}

		/// <summary>
		/// Gets or sets a value indicating whether there are unsaved changes.
		/// </summary>
		public bool IsDirty
		{
			get => this.isDirty;
			set => this.Set(ref this.isDirty, value);
		}

		/// <summary>
		/// Loads policy context for the editor and resolves scope-specific policy path.
		/// </summary>
		/// <param name="solutionPath">The currently open solution path.</param>
		/// <param name="projectPaths">All loaded project paths available for project-scoped editing.</param>
		/// <param name="preferredPolicyType">Preferred policy scope to select when available.</param>
		public void LoadContext(string solutionPath, IReadOnlyList<string> projectPaths, PolicyScopeType? preferredPolicyType)
		{
			this.solutionPath = solutionPath ?? string.Empty;
			this.projectPaths = projectPaths ?? Array.Empty<string>();

			this.RefreshAvailableProjects();
			this.RefreshAvailablePolicyTypes();

			var selectedType = preferredPolicyType ?? this.policyType;

			if (!this.availablePolicyTypes.Contains(selectedType))
			{
				selectedType = this.ResolveFallbackPolicyType();
			}

			_ = this.Set(ref this.policyType, selectedType, nameof(this.PolicyType));
			this.UpdatePolicyPathFromType();
			this.LoadFromCurrentPolicyType();
		}

		/// <summary>
		/// Saves the current view model state to the policy file path.
		/// </summary>
		public void Save()
		{
			if (string.IsNullOrWhiteSpace(this.policyPath))
			{
				this.StatusMessage = "No policy path set.";
				return;
			}

			try
			{
				var document = this.BuildDocument();
				new PolicyService().Save(this.policyPath, document);
				this.loadedDocument = ClonePolicyDocument(document);
				this.StatusMessage = $"Saved {this.PolicyTypeLabel} policy: {PathRedactionService.RedactPath(this.policyPath)}";
				this.IsDirty = false;
			}
			catch (Exception ex)
			{
				this.StatusMessage = $"Failed to save policy: {ex.Message}";
			}
		}

		/// <summary>
		/// Saves the current view model state and returns whether the operation succeeded.
		/// </summary>
		/// <returns><c>true</c> when the policy file was saved; otherwise <c>false</c>.</returns>
		public Task<bool> SaveAsync()
		{
			var saved = false;

			if (!string.IsNullOrWhiteSpace(this.policyPath))
			{
				try
				{
					var document = this.BuildDocument();
					new PolicyService().Save(this.policyPath, document);
					this.loadedDocument = ClonePolicyDocument(document);
					this.StatusMessage = $"Saved {this.PolicyTypeLabel} policy: {PathRedactionService.RedactPath(this.policyPath)}";
					this.IsDirty = false;
					saved = true;
				}
				catch (Exception ex)
				{
					this.StatusMessage = $"Failed to save policy: {ex.Message}";
				}
			}
			else
			{
				this.StatusMessage = "No policy path set.";
			}

			return Task.FromResult(saved);
		}

		/// <summary>
		/// Determines whether the current editor values differ from the loaded policy.
		/// </summary>
		/// <returns><c>true</c> when policy values changed; otherwise <c>false</c>.</returns>
		public bool HasPolicyChanges()
		{
			if (this.loadedDocument == null)
			{
				return true;
			}

			var current = this.BuildDocument();

			return !AreEquivalentPolicyValues(current, this.loadedDocument);
		}

		/// <summary>
		/// Determines whether the current policy values are more permissive than the loaded policy.
		/// </summary>
		/// <returns><c>true</c> when the current values are more permissive; otherwise <c>false</c>.</returns>
		public bool IsCurrentPolicyMorePermissive()
		{
			if (this.loadedDocument == null)
			{
				return false;
			}

			var current = this.BuildDocument();

			return IsMorePermissive(current, this.loadedDocument);
		}

		/// <summary>
		/// Builds a <see cref="PolicyDocument"/> from the current view model state.
		/// </summary>
		/// <returns>A populated policy document.</returns>
		private PolicyDocument BuildDocument()
		{
			var document = new PolicyDocument
			{
				Mode                        = this.mode,
				BaselineRequired            = this.baselineRequired,
				StrictMode                  = this.strictMode,
				IncompleteAnalysisAction    = this.incompleteAnalysisAction,
				UnapprovedPackageSourceAction = this.unapprovedPackageSourceAction,
				Version                     = 1
			};

			document.MinimumActionBySeverity[FindingSeverity.Info]     = this.infoAction;
			document.MinimumActionBySeverity[FindingSeverity.Low]      = this.lowAction;
			document.MinimumActionBySeverity[FindingSeverity.Medium]   = this.mediumAction;
			document.MinimumActionBySeverity[FindingSeverity.High]     = this.highAction;
			document.MinimumActionBySeverity[FindingSeverity.Critical] = this.criticalAction;

			return document;
		}

		/// <summary>
		/// Applies a loaded policy document to the view model properties.
		/// </summary>
		/// <param name="document">The policy document to apply.</param>
		private void ApplyDocument(PolicyDocument document)
		{
			this.mode                         = document.Mode;
			this.baselineRequired             = document.BaselineRequired;
			this.strictMode                   = document.StrictMode;
			this.incompleteAnalysisAction     = document.IncompleteAnalysisAction;
			this.unapprovedPackageSourceAction = document.UnapprovedPackageSourceAction;

			this.infoAction     = GetSeverityAction(document, FindingSeverity.Info,     PolicyAction.Allow);
			this.lowAction      = GetSeverityAction(document, FindingSeverity.Low,      PolicyAction.Warn);
			this.mediumAction   = GetSeverityAction(document, FindingSeverity.Medium,   PolicyAction.RequireApproval);
			this.highAction     = GetSeverityAction(document, FindingSeverity.High,     PolicyAction.Block);
			this.criticalAction = GetSeverityAction(document, FindingSeverity.Critical, PolicyAction.Block);

			this.OnPropertyChanged(nameof(this.Mode));
			this.OnPropertyChanged(nameof(this.BaselineRequired));
			this.OnPropertyChanged(nameof(this.StrictMode));
			this.OnPropertyChanged(nameof(this.IncompleteAnalysisAction));
			this.OnPropertyChanged(nameof(this.UnapprovedPackageSourceAction));
			this.OnPropertyChanged(nameof(this.InfoAction));
			this.OnPropertyChanged(nameof(this.LowAction));
			this.OnPropertyChanged(nameof(this.MediumAction));
			this.OnPropertyChanged(nameof(this.HighAction));
			this.OnPropertyChanged(nameof(this.CriticalAction));
		}

		/// <summary>
		/// Returns the configured action for a severity level, falling back to a default.
		/// </summary>
		/// <param name="document">The policy document.</param>
		/// <param name="severity">The severity level.</param>
		/// <param name="fallback">Default action when not configured.</param>
		/// <returns>The resolved policy action.</returns>
		private static PolicyAction GetSeverityAction(PolicyDocument document, FindingSeverity severity, PolicyAction fallback)
		{
			return document.MinimumActionBySeverity.TryGetValue(severity, out var action) ? action : fallback;
		}

		/// <summary>
		/// Sets a property value and raises <see cref="PropertyChanged"/>.
		/// </summary>
		/// <typeparam name="T">Property type.</typeparam>
		/// <param name="field">Backing field reference.</param>
		/// <param name="value">New value.</param>
		/// <param name="name">Property name (compiler-filled).</param>
		private bool Set<T>(ref T field, T value, [CallerMemberName] string name = "")
		{
			if (EqualityComparer<T>.Default.Equals(field, value))
			{
				return false;
			}

			field = value;
			this.OnPropertyChanged(name);

			return true;
		}

		/// <summary>
		/// Sets a property value, marks the view model dirty, and raises <see cref="PropertyChanged"/>.
		/// </summary>
		/// <typeparam name="T">Property type.</typeparam>
		/// <param name="field">Backing field reference.</param>
		/// <param name="value">New value.</param>
		/// <param name="name">Property name (compiler-filled).</param>
		private void SetDirty<T>(ref T field, T value, [CallerMemberName] string name = "")
		{
			if (EqualityComparer<T>.Default.Equals(field, value))
			{
				return;
			}

			field = value;
			this.IsDirty = true;
			this.OnPropertyChanged(name);
		}

		/// <summary>
		/// Raises the <see cref="PropertyChanged"/> event.
		/// </summary>
		/// <param name="name">Name of the changed property.</param>
		private void OnPropertyChanged(string name)
		{
			this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
		}

		/// <summary>
		/// Rebuilds the list of policy scopes that are valid for the current context.
		/// </summary>
		private void RefreshAvailableProjects()
		{
			this.availableProjects.Clear();

			foreach (var path in this.projectPaths)
			{
				if (!string.IsNullOrWhiteSpace(path))
				{
					this.availableProjects.Add(new SolutionProjectOptionViewModel
					{
						Name = Path.GetFileName(path),
						Path = path
					});
				}
			}

			this.selectedProject = this.availableProjects.FirstOrDefault();
			this.OnPropertyChanged(nameof(this.AvailableProjects));
			this.OnPropertyChanged(nameof(this.SelectedProject));
		}

		private void RefreshAvailablePolicyTypes()
		{
			this.availablePolicyTypes.Clear();
			this.availablePolicyTypes.Add(PolicyScopeType.Machine);

			if (!string.IsNullOrWhiteSpace(this.solutionPath) && File.Exists(this.solutionPath))
			{
				this.availablePolicyTypes.Add(PolicyScopeType.Solution);
			}

			if (this.availableProjects.Count > 0)
			{
				this.availablePolicyTypes.Add(PolicyScopeType.Project);
			}

			this.OnPropertyChanged(nameof(this.AvailablePolicyTypes));
		}

		/// <summary>
		/// Resolves the fallback policy scope when the preferred scope is unavailable.
		/// </summary>
		/// <returns>The fallback policy scope type.</returns>
		private PolicyScopeType ResolveFallbackPolicyType()
		{
			if (this.availablePolicyTypes.Contains(PolicyScopeType.Solution))
			{
				return PolicyScopeType.Solution;
			}

			return PolicyScopeType.Machine;
		}

		/// <summary>
		/// Loads policy values for the currently selected policy scope.
		/// </summary>
		private void LoadFromCurrentPolicyType()
		{
			if (string.IsNullOrWhiteSpace(this.PolicyPath))
			{
				var defaultsWhenPathMissing = new PolicyService().CreateDefault();
				this.loadedDocument = null;
				this.ApplyDocument(defaultsWhenPathMissing);
				this.StatusMessage = "No policy file path is available for current policy scope.";
				this.IsDirty = false;
				return;
			}

			if (!File.Exists(this.PolicyPath))
			{
				var defaults = new PolicyService().CreateDefault();
				this.loadedDocument = null;
				this.ApplyDocument(defaults);
				this.StatusMessage = $"No {this.PolicyTypeLabel} policy file found — showing defaults. Save to create the file.";
				this.IsDirty = true;
				return;
			}

			try
			{
				var service = new PolicyService();
				var document = service.LoadUnsigned(this.PolicyPath);
				this.loadedDocument = ClonePolicyDocument(document);
				this.ApplyDocument(document);
				this.StatusMessage = $"Loaded {this.PolicyTypeLabel} policy: {PathRedactionService.RedactPath(this.PolicyPath)}";
				this.IsDirty = false;
			}
			catch (Exception ex)
			{
				this.loadedDocument = null;
				this.StatusMessage = $"Failed to load policy: {ex.Message}";
			}
		}

		/// <summary>
		/// Updates the policy path and scope label based on the selected policy type.
		/// </summary>
		private void UpdatePolicyPathFromType()
		{
			var policyService = new PolicyService();
			this.OnPropertyChanged(nameof(this.IsProjectDropdownVisible));

			switch (this.PolicyType)
			{
				case PolicyScopeType.Machine:
					this.PolicyTypeLabel = "Machine";
					this.PolicyPath = policyService.GetMachinePolicyPath();
					return;
				case PolicyScopeType.Project:
					this.PolicyTypeLabel = "Project";
					var projectPath = this.selectedProject?.Path ?? string.Empty;

					if (!string.IsNullOrWhiteSpace(projectPath))
					{
						this.PolicyPath = policyService.GetProjectPolicyPath(projectPath);
					}
					else
					{
						this.PolicyPath = string.Empty;
					}

					return;
				default:
					this.PolicyTypeLabel = "Solution";
					var solutionDirectory = Path.GetDirectoryName(this.solutionPath);

					if (!string.IsNullOrWhiteSpace(solutionDirectory))
					{
						this.PolicyPath = policyService.GetRepositoryPolicyPath(solutionDirectory);
					}
					else
					{
						this.PolicyPath = string.Empty;
					}

					return;
			}
		}

		/// <summary>
		/// Creates a detached clone of the provided policy document.
		/// </summary>
		/// <param name="source">The policy document to clone.</param>
		/// <returns>A cloned policy document.</returns>
		private static PolicyDocument ClonePolicyDocument(PolicyDocument source)
		{
			var clone = new PolicyDocument
			{
				Version = source.Version,
				Mode = source.Mode,
				BaselineRequired = source.BaselineRequired,
				StrictMode = source.StrictMode,
				IncompleteAnalysisAction = source.IncompleteAnalysisAction,
				UnapprovedPackageSourceAction = source.UnapprovedPackageSourceAction
			};

			clone.MinimumActionBySeverity[FindingSeverity.Info] = GetSeverityAction(source, FindingSeverity.Info, PolicyAction.Allow);
			clone.MinimumActionBySeverity[FindingSeverity.Low] = GetSeverityAction(source, FindingSeverity.Low, PolicyAction.Warn);
			clone.MinimumActionBySeverity[FindingSeverity.Medium] = GetSeverityAction(source, FindingSeverity.Medium, PolicyAction.RequireApproval);
			clone.MinimumActionBySeverity[FindingSeverity.High] = GetSeverityAction(source, FindingSeverity.High, PolicyAction.Block);
			clone.MinimumActionBySeverity[FindingSeverity.Critical] = GetSeverityAction(source, FindingSeverity.Critical, PolicyAction.Block);

			return clone;
		}

		/// <summary>
		/// Determines whether two policy documents are equivalent for editor-relevant values.
		/// </summary>
		/// <param name="left">The first policy document.</param>
		/// <param name="right">The second policy document.</param>
		/// <returns><c>true</c> when equivalent; otherwise <c>false</c>.</returns>
		private static bool AreEquivalentPolicyValues(PolicyDocument left, PolicyDocument right)
		{
			if (!string.Equals(left.Mode, right.Mode, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			if (left.BaselineRequired != right.BaselineRequired || left.StrictMode != right.StrictMode)
			{
				return false;
			}

			if (left.IncompleteAnalysisAction != right.IncompleteAnalysisAction || left.UnapprovedPackageSourceAction != right.UnapprovedPackageSourceAction)
			{
				return false;
			}

			if (GetSeverityAction(left, FindingSeverity.Info, PolicyAction.Allow) != GetSeverityAction(right, FindingSeverity.Info, PolicyAction.Allow))
			{
				return false;
			}

			if (GetSeverityAction(left, FindingSeverity.Low, PolicyAction.Warn) != GetSeverityAction(right, FindingSeverity.Low, PolicyAction.Warn))
			{
				return false;
			}

			if (GetSeverityAction(left, FindingSeverity.Medium, PolicyAction.RequireApproval) != GetSeverityAction(right, FindingSeverity.Medium, PolicyAction.RequireApproval))
			{
				return false;
			}

			if (GetSeverityAction(left, FindingSeverity.High, PolicyAction.Block) != GetSeverityAction(right, FindingSeverity.High, PolicyAction.Block))
			{
				return false;
			}

			if (GetSeverityAction(left, FindingSeverity.Critical, PolicyAction.Block) != GetSeverityAction(right, FindingSeverity.Critical, PolicyAction.Block))
			{
				return false;
			}

			return true;
		}

		/// <summary>
		/// Determines whether the current policy is more permissive than the previous policy.
		/// </summary>
		/// <param name="current">The current policy values.</param>
		/// <param name="previous">The previous policy values.</param>
		/// <returns><c>true</c> when current policy is more permissive; otherwise <c>false</c>.</returns>
		private static bool IsMorePermissive(PolicyDocument current, PolicyDocument previous)
		{
			if (string.Equals(previous.Mode, "block", StringComparison.OrdinalIgnoreCase) && !string.Equals(current.Mode, "block", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			if (previous.BaselineRequired && !current.BaselineRequired)
			{
				return true;
			}

			if (previous.StrictMode && !current.StrictMode)
			{
				return true;
			}

			if (current.IncompleteAnalysisAction < previous.IncompleteAnalysisAction)
			{
				return true;
			}

			if (current.UnapprovedPackageSourceAction < previous.UnapprovedPackageSourceAction)
			{
				return true;
			}

			if (GetSeverityAction(current, FindingSeverity.Info, PolicyAction.Allow) < GetSeverityAction(previous, FindingSeverity.Info, PolicyAction.Allow))
			{
				return true;
			}

			if (GetSeverityAction(current, FindingSeverity.Low, PolicyAction.Warn) < GetSeverityAction(previous, FindingSeverity.Low, PolicyAction.Warn))
			{
				return true;
			}

			if (GetSeverityAction(current, FindingSeverity.Medium, PolicyAction.RequireApproval) < GetSeverityAction(previous, FindingSeverity.Medium, PolicyAction.RequireApproval))
			{
				return true;
			}

			if (GetSeverityAction(current, FindingSeverity.High, PolicyAction.Block) < GetSeverityAction(previous, FindingSeverity.High, PolicyAction.Block))
			{
				return true;
			}

			if (GetSeverityAction(current, FindingSeverity.Critical, PolicyAction.Block) < GetSeverityAction(previous, FindingSeverity.Critical, PolicyAction.Block))
			{
				return true;
			}

			return false;
		}
	}
}
