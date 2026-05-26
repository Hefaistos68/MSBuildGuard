using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using EnvDTE;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Discovers project paths from Solution Explorer selection and loaded solution hierarchy.
	/// </summary>
	internal sealed class SolutionExplorerProjectDiscoveryService
	{
		/// <summary>
		/// Gets the selected project path from Solution Explorer if selection is project-scoped.
		/// </summary>
		/// <returns>Selected project path or null when no project/item selection is active.</returns>
		public static string? GetSelectedProjectPath()
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			var monitorSelection = (IVsMonitorSelection)Package.GetGlobalService(typeof(SVsShellMonitorSelection));

			if (monitorSelection == null)
			{
				return null;
			}

			monitorSelection.GetCurrentSelection(out var hierarchyPointer, out var projectItemId, out var _, out var _);

			if (hierarchyPointer == IntPtr.Zero)
			{
				return null;
			}

			try
			{
				var hierarchy = (IVsHierarchy)Marshal.GetObjectForIUnknown(hierarchyPointer);

				if (hierarchy == null)
				{
					return null;
				}

				hierarchy.GetProperty(projectItemId, (int)__VSHPROPID.VSHPROPID_ExtObject, out var extObject);

				if (extObject is Project project)
				{
					return project.FullName;
				}

				if (extObject is ProjectItem projectItem && projectItem.ContainingProject != null)
				{
					return projectItem.ContainingProject.FullName;
				}

				hierarchy.GetCanonicalName(projectItemId, out var canonicalName);
				return canonicalName;
			}
			finally
			{
				Marshal.Release(hierarchyPointer);
			}
		}

		/// <summary>
		/// Gets all currently loaded project paths from the open solution.
		/// </summary>
		/// <returns>Collection of loaded project file paths.</returns>
		public static IReadOnlyList<string> GetLoadedProjectPaths()
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			var solution = (IVsSolution)Package.GetGlobalService(typeof(SVsSolution));
			var projectPaths = new List<string>();

			if (solution == null)
			{
				return projectPaths;
			}

			if (solution.GetProjectEnum((uint)__VSENUMPROJFLAGS.EPF_LOADEDINSOLUTION, Guid.Empty, out var enumHierarchies) != 0 || enumHierarchies == null)
			{
				return projectPaths;
			}

			var fetched = 0u;
			var hierarchies = new IVsHierarchy[1];

			while (enumHierarchies.Next(1, hierarchies, out fetched) == 0 && fetched == 1)
			{
				var hierarchy = hierarchies[0];

				if (hierarchy == null)
				{
					continue;
				}

				hierarchy.GetProperty((uint)VSConstants.VSITEMID_ROOT, (int)__VSHPROPID.VSHPROPID_ExtObject, out var extObject);

				if (extObject is Project project && !string.IsNullOrWhiteSpace(project.FullName))
				{
					projectPaths.Add(project.FullName);
				}
			}

			return projectPaths;
		}
	}
}
