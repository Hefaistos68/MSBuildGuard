namespace MSBuildGuard.VisualStudio.Models
{
	/// <summary>
	/// Represents a project selection option in the solution review dropdown.
	/// </summary>
	public sealed class SolutionProjectOptionViewModel
	{
		/// <summary>
		/// Gets or sets the display name.
		/// </summary>
		public string Name { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the backing path for filtering.
		/// </summary>
		public string Path { get; set; } = string.Empty;
	}
}
