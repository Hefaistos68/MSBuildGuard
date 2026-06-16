# Advanced Trust Management

MSBuild Guard provides advanced trust management options designed to balance security with developer productivity, supporting both solo developers and enterprise team environments.

## Key Management Modes

Upon the first startup of MSBuild Guard (on both Visual Studio and VS Code), you are prompted to choose your trust key management mode:

1. **Solo Developer (Local DPAPI)**
   - **How it works**: Trust store signing keys are unique to your local machine and encrypted/isolated using Windows Data Protection API (DPAPI) or OS-level keychain mechanisms.
   - **Sharing**: Because the keys are machine-isolated, trust files cannot be shared in source repositories. The option to allow repository trust sharing is disabled and unavailable.
   - **Target Audience**: Single developers who want local security protection without certificate overhead.

2. **Team Environment (Asymmetric Certificates)**
   - **How it works**: Trust files are signed asymmetrically using enterprise certificates. To verify shared trust files, the corresponding public verification certificate must be present in the machine/user trust store (`TrustedPeople`).
   - **Sharing**: Enables sharing signed trust files (`trust.json` and `.msbuildguard/` configuration) within repositories, which can then be validated automatically by team members' installations.
   - **Target Audience**: Development teams sharing a shared repository code base.

---

## Asymmetric Signing and Repository Pinning

To prevent malicious actors or malware from tampering with shared trust configurations, MSBuild Guard enforces two key protections when running in Asymmetric Certificates mode:

### Companion File Signature Enforcement
When asymmetric signing is active, the `.msbuildguard/trust.json` file is signed, and its signature is stored in a companion file named `trust.json.signature` directly next to it in the same directory.
- If `enforceAsymmetricSignatures` is enabled, any solution or project trust store loaded *must* have a matching valid companion signature file, or MSBuild Guard will reject it and block the build.

### Repository Pinning
To prevent downgrading attacks where a repository signed asymmetrically is checked out and its signature is stripped (or the global setting is disabled by malware), MSBuild Guard maintains a DPAPI-encrypted database of "Asymmetric Required" repository paths.
- **How it triggers**: The first time any solution or project is loaded while `enforceAsymmetricSignatures` is active and successfully validates an asymmetric signature, its path is permanently recorded in the local pinned repositories database.
- **Enforcement**: Future loads of this repository will *always* strictly require a valid asymmetric signature, even if the global `enforceAsymmetricSignatures` setting is later turned off, unless a trust purge is explicitly executed for that solution.

---

## Trust Purging

To ensure that security transitions are explicit and secure, MSBuild Guard provides mechanisms to completely purge trust data:

### Settings Downgrade Purge
If you disable `enforceAsymmetricSignatures` (changing the value from `true` to `false` in options), a warning confirmation dialog is shown. If you proceed:
- All local user-level trust stores are deleted.
- The currently loaded solution and project trust stores are deleted.
- MSBuild Guard scans the IDE's recent projects/solutions metadata (MRU lists) and recursively deletes any `.msbuildguard/trust.json` files found under those solution directories.

### UI Trust Purge Actions
1. **Remove all Solution Trusts**: Under the **Security** menu in Visual Studio, or via Command Palette in VS Code, select "Remove all Solution Trusts" to confirm and delete the active solution-level `trust.json`.
2. **Remove all Project Trusts**: In the **Security Review** tool window:
   - When the "Only Trusted Issues" checkbox is unchecked, the "Remove all project trusts" button is enabled.
   - Clicking this button recursively searches the solution directory for all project-level `.msbuildguard/trust.json` files and prompts you for confirmation before permanently deleting them.
3. **Remove all User Trusts**: Under options or Command Palette, trigger user trust deletion to remove global user-level trusts.

---

## Certificate Pinning and Enterprise Setup

To secure shared policies and trust stores in enterprise environments, MSBuild Guard supports X509 certificate signing and strict CA/Root CA pinning. This prevents supply chain attacks, downgrade attempts, or local policy modifications by malicious software.

### Environment Configuration Variables

The following system-level environment variables configure the verification engine:

| Environment Variable | Description |
| :--- | :--- |
| `MSBUILDGUARD_ROOT_CA_THUMBPRINT` | Hex thumbprint of the designated intermediate or root Certificate Authority. When configured, MSBuild Guard only accepts policy and trust store signatures issued by this CA. |
| `MSBUILDGUARD_POLICY_SIGNING_CERT_THUMBPRINT` | Thumbprint of the certificate used by administrators to sign policy and trust files. |
| `MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE` | Set to `true` (or `1`) to allow certificates from `CurrentUser\TrustedPeople` to verify signatures (useful for development/testing). Defaults to `false` (only `LocalMachine\TrustedPeople` is trusted). |

---

## Enterprise PKI and Group Policy (GPO) Deployment

For corporate settings, follow this deployment pipeline to establish centralized control over MSBuild Guard:

### 1. Central CA Certificate Provisioning
1. Generate or assign a dedicated signing certificate from your Enterprise PKI.
2. The private key must remain securely stored (e.g., in a Hardware Security Module (HSM) or an offline administration vault).
3. The public certificate (.cer) must be distributed to all developer workstations.

### 2. Distribute Public Certificate via GPO or Intune
To ensure developers can verify policies, import the public signing certificate to the **Trusted People** store on the local machine (`LocalMachine\TrustedPeople`):

* **Using Active Directory Group Policy (GPO)**:
  1. Open Group Policy Management Console.
  2. Edit or create a GPO. Navigate to: `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Public Key Policies -> Trusted People`.
  3. Right-click **Trusted People** and select **Import**. Follow the wizard to import the public certificate.
* **Using Microsoft Intune (MDM)**:
  1. Navigate to the Microsoft Intune admin center.
  2. Create a new device configuration profile using the **Trusted Certificate** template.
  3. Upload the `.cer` certificate file and assign the profile to the developer device groups.

### 3. Enforce CA Pinning via Environment Variable Group Policy
Deploy the `MSBUILDGUARD_ROOT_CA_THUMBPRINT` variable across developer machines:
1. In your Group Policy Editor, navigate to: `Computer Configuration -> Policies -> Windows Settings -> Environment`. (Or `Computer Configuration -> Preferences -> Windows Settings -> Environment`)
2. Right-click, select `New -> Environment Variable`.
3. Set **Action** to `Update`, **Name** to `MSBUILDGUARD_ROOT_CA_THUMBPRINT`, and **Value** to the SHA-1 thumbprint of your Root/Intermediate CA.
4. Set **User Variable** to `false` (System Variable).

---

## Solo Developer Trust Management Setup

For independent developers who do not need certificate signing, the **Solo Developer (Local DPAPI)** setup is recommended:

1. **Onboarding Select**: Select **Solo Developer (Local DPAPI)** when prompted on first startup.
2. **Machine Key Generation**: MSBuild Guard automatically generates a machine-specific key in `%LOCALAPPDATA%\MSBuildGuard\machine.key` and encrypts it using Windows DPAPI. Only processes running under your Windows user account can read this key to verify or sign trust databases.
3. **Repository Exclusion**: Add `.msbuildguard/` folder entries to your local `.gitignore` files to avoid committing DPAPI-signed files, as they are not valid on other machines.
