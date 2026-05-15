using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// Read-only information dialog that displays Authenticode and assembly metadata for a NuGet package assembly.
	/// </summary>
	public partial class AssemblyInformationDialog : Window
	{
		/// <summary>The file-object type constant for <c>SHObjectProperties</c>.</summary>
		private const uint ShopFilepath = 0x2;

		/// <summary>Resolved certificate Subject DN; set after Window_Loaded.</summary>
		private string resolvedSignerSubject = string.Empty;

		/// <summary>Resolved signer display name; set after Window_Loaded.</summary>
		private string resolvedSignerName = string.Empty;

		/// <summary>Resolved certificate issuer; set after Window_Loaded.</summary>
		private string resolvedIssuer = string.Empty;

		/// <summary>Resolved certificate thumbprint; set after Window_Loaded.</summary>
		private string resolvedThumbprint = string.Empty;

		/// <summary>Resolved certificate serial number; set after Window_Loaded.</summary>
		private string resolvedSerialNumber = string.Empty;

		/// <summary>
		/// Gets or sets the assembly name.
		/// </summary>
		public string AssemblyName { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the assembly version.
		/// </summary>
		public string AssemblyVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the resolved path to the assembly PE file.
		/// </summary>
		public string AssemblyPath { get; set; } = string.Empty;

		/// <summary>
		/// Initializes a new instance of the <see cref="AssemblyInformationDialog"/> class.
		/// </summary>
		public AssemblyInformationDialog()
		{
			InitializeComponent();
		}

		/// <summary>
		/// Populates the UI fields when the dialog is loaded.
		/// </summary>
		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			AssemblyNameTextBlock.Text    = this.AssemblyName;
			AssemblyVersionTextBlock.Text = this.AssemblyVersion;
			AssemblyPathTextBlock.Text    = PathRedactionService.RedactPath(this.AssemblyPath);

			var signature = new AssemblySignatureService().ReadSignature(this.AssemblyPath);

			this.resolvedSignerSubject = signature.Subject;
			this.resolvedSignerName    = signature.Signer;
			this.resolvedIssuer        = signature.Issuer;
			this.resolvedThumbprint    = signature.Thumbprint;
			this.resolvedSerialNumber  = signature.SerialNumber;

			AssemblySignerTextBlock.Text  = signature.HasEmbeddedSignature ? (string.IsNullOrWhiteSpace(signature.Signer) ? "Not available" : signature.Signer) : "No embedded signature";
			AssemblyIssuerTextBlock.Text  = signature.HasEmbeddedSignature ? (string.IsNullOrWhiteSpace(signature.Issuer) ? "Not available" : signature.Issuer) : "Not available";
			AssemblySubjectTextBlock.Text = signature.HasEmbeddedSignature ? (string.IsNullOrWhiteSpace(signature.Subject) ? "Not available" : signature.Subject) : "Not available";

			OpenPropertiesButton.IsEnabled = !string.IsNullOrWhiteSpace(this.AssemblyPath) &&
				System.IO.File.Exists(this.AssemblyPath);

			var hasAssemblyIdentity = !string.IsNullOrWhiteSpace(this.AssemblyName) && !string.IsNullOrWhiteSpace(this.AssemblyVersion);
			var trustStoreService = new TrustStoreService();
			var trustPath = trustStoreService.GetDefaultUserTrustPath();
			var trustStore = trustStoreService.Load(trustPath);
			var isSignerTrusted = signature.IsSignatureValid &&
				!string.IsNullOrWhiteSpace(signature.Subject) &&
				trustStoreService.IsSignerTrusted(trustStore, this.resolvedThumbprint, this.resolvedSignerSubject, this.resolvedIssuer, this.resolvedSerialNumber);
			var isAssemblyTrusted = hasAssemblyIdentity &&
				trustStoreService.IsAssemblyApproved(trustStore, this.AssemblyName, this.AssemblyVersion);

			// Trust actions are only meaningful when the Authenticode signature verifies successfully.
			TrustSignerButton.IsEnabled = signature.IsSignatureValid && !string.IsNullOrWhiteSpace(signature.Subject) && !isSignerTrusted;
			TrustSignerButton.Content = isSignerTrusted ? "Signer Trusted ✓" : "Trust Signer";
			TrustAssemblyButton.IsEnabled = hasAssemblyIdentity && signature.IsSignatureValid && !isAssemblyTrusted;
			TrustAssemblyButton.Content = isAssemblyTrusted ? "Assembly Trusted ✓" : "Trust Assembly";
		}

		/// <summary>
		/// Opens the Windows Explorer file properties dialog for the resolved assembly path.
		/// </summary>
		private void OpenPropertiesButton_Click(object sender, RoutedEventArgs e)
		{
			if (string.IsNullOrWhiteSpace(this.AssemblyPath) || !System.IO.File.Exists(this.AssemblyPath))
			{
				return;
			}

			var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
			SHObjectProperties(hwnd, ShopFilepath, this.AssemblyPath, null);
		}

		/// <summary>
		/// Adds a signer-level trust entry so that any assembly signed by the same certificate
		/// is automatically approved in future scans.
		/// </summary>
		private void TrustSignerButton_Click(object sender, RoutedEventArgs e)
		{
			if (string.IsNullOrWhiteSpace(this.resolvedSignerSubject))
			{
				return;
			}

			var confirm = MessageBox.Show(
				$"Trust all assemblies signed by:\n\n  {this.resolvedSignerName}\n\nThis will approve any package whose certificate Subject matches this signer. Continue?",
				"Trust Signer",
				MessageBoxButton.YesNo,
				MessageBoxImage.Question);

			if (confirm != MessageBoxResult.Yes)
			{
				return;
			}

			var trustStoreService = new TrustStoreService();
			var trustPath = trustStoreService.GetDefaultUserTrustPath();
			var userSid   = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";
			var reason    = $"Signer trusted from Assembly Information dialog on {System.DateTime.UtcNow:O}";

			trustStoreService.AddSignerTrust(
				trustPath,
				this.resolvedThumbprint,
				this.resolvedSignerSubject,
				this.resolvedSignerName,
				this.resolvedIssuer,
				this.resolvedSerialNumber,
				reason,
				userSid);

			TrustSignerButton.IsEnabled = false;
			TrustSignerButton.Content   = "Signer Trusted ✓";
		}

		/// <summary>
		/// Adds an assembly-level trust entry using the same trust flow as the Solution Security Review.
		/// </summary>
		private void TrustAssemblyButton_Click(object sender, RoutedEventArgs e)
		{
			if (string.IsNullOrWhiteSpace(this.AssemblyName) || string.IsNullOrWhiteSpace(this.AssemblyVersion) || string.IsNullOrWhiteSpace(this.AssemblyPath))
			{
				return;
			}

			var trustDialog = new TrustAssemblyDialog
			{
				AssemblyName    = this.AssemblyName,
				AssemblyVersion = this.AssemblyVersion,
				AssemblyPath    = this.AssemblyPath,
				AssemblySigner  = this.resolvedSignerName,
				AssemblyIssuer  = this.resolvedIssuer,
				AssemblySubject = this.resolvedSignerSubject,
				Owner           = this,
				WindowStartupLocation = WindowStartupLocation.CenterOwner
			};

			if (trustDialog.ShowDialog() != true)
			{
				return;
			}

			var trustStoreService = new TrustStoreService();
			var trustPath = trustStoreService.GetDefaultUserTrustPath();
			var userSid = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

			trustStoreService.AddAssemblyTrust(
				trustPath,
				this.AssemblyName,
				this.AssemblyVersion,
				trustDialog.TrustReason,
				userSid,
				this.resolvedSignerName,
				this.resolvedIssuer,
				this.resolvedSignerSubject);

			TrustAssemblyButton.IsEnabled = false;
			TrustAssemblyButton.Content = "Assembly Trusted ✓";
		}

		/// <summary>
		/// Closes the dialog.
		/// </summary>
		private void CloseButton_Click(object sender, RoutedEventArgs e)
		{
			this.Close();
		}

		/// <summary>
		/// Opens the shell properties dialog for a file-system object.
		/// </summary>
		/// <param name="hwnd">Owner window handle.</param>
		/// <param name="shopObjectType">Object type; <c>0x2</c> for a file path.</param>
		/// <param name="pszObjectName">Full path to the file.</param>
		/// <param name="pszPropertyPage">Optional property page name; pass <see langword="null"/> to open the default page.</param>
		/// <returns><see langword="true"/> if the dialog was shown successfully.</returns>
		[DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
		private static extern bool SHObjectProperties(
			System.IntPtr hwnd,
			uint shopObjectType,
			[MarshalAs(UnmanagedType.LPWStr)] string pszObjectName,
			[MarshalAs(UnmanagedType.LPWStr)] string? pszPropertyPage);
	}
}