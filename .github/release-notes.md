## Defender Control v2.1.0 — first public release

Pure-Python reimplementation of Sordum **Defender Control v2.1** for Windows 10/11.

### Downloads

| File | Description |
|------|-------------|
| `dControl.exe` | Windowed GUI, self-contained, `requireAdministrator` manifest (like the original) |
| `dcontrol-cli.exe` | Console CLI: `status`, `disable`, `enable` |
| `defender-control-windows.zip` | Both executables + `SHA256SUMS.txt` |

No Python installation is required. Both executables are single-file builds.

### What it does

* **Status** — read-only snapshot of the Defender services, start types and policy values.
* **Disable** — stops the Security Center and the Defender service family, writes the group-policy
  and direct registry values, adds IFEO blocks for Defender tools, disables SecurityHealth autostart
  and sets the Defender services to *Disabled*.
* **Enable** — reverses every step and restores the original service start types.

### Notes

* A **reboot is recommended** after disabling or enabling.
* Disabling Windows Defender leaves the machine unprotected — use it only on machines you own.
* Windows SmartScreen may warn about unsigned binaries (the executables are not code-signed).

Verify your download with `SHA256SUMS.txt`:

```powershell
Get-FileHash .\dControl.exe -Algorithm SHA256
```
