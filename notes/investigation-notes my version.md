# Investigation Notes

## Investigated File

`C:\Windows\System32\notepad.exe`

The file existed at the expected path.

```text
FullName       : C:\Windows\System32\notepad.exe
Length         : 360448
CreationTime   : 09-09-2026 09:56:13
LastWriteTime  : 09-09-2026 09:56:13
LastAccessTime : 17-09-2026 12:58:09
```

## Hashes

The following hashes were collected:

```text
MD5    : 8A1D8175CCCA97054CDB25ACBB4CC07E
SHA1   : 76CD26B59923157E09D2BC927BA8FB059F3155DC
SHA256 : 468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The SHA256 value provides the primary identifier for the exact file contents investigated during this lab.

## Version Metadata

The file reported:

```text
FileVersion      : 10.0.26100.8457 (WinBuild.160101.0800)
ProductName      : Microsoft® Windows® Operating System
ProductVersion   : 10.0.26100.8457
CompanyName      : Microsoft Corporation
OriginalFilename : NOTEPAD.EXE.MUI
InternalName     : Notepad
LegalCopyright   : © Microsoft Corporation. All rights reserved.
Comments         :
```

These values are embedded version-resource metadata and should be treated as supporting information rather than independent proof of file authenticity.

## Digital Signature

Authenticode verification returned:

```text
Status        : Valid
StatusMessage : Signature verified.
```

Signer certificate details:

```text
Subject    : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
Issuer     : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation
NotBefore  : 17-04-2026 00:39:15
NotAfter   : 18-10-2026 00:39:15
Thumbprint : DC91E564D5BC1E3A8E02D6A8508682ABEA8A2443
```

The observed signature and certificate information are consistent with a Microsoft-signed Windows component.

## PE Architecture

The PE header was examined directly using PowerShell.

Observed result:

```text
Architecture: x64 (64-bit)
```

This was derived from the PE Machine field.

## Alternate Data Streams

The file was checked for alternate data streams.

Observed output showed only the normal:

```text
:$DATA
```

stream.

No `Zone.Identifier` stream was shown in the captured output.

This does not establish how the file originally arrived on the system.

## Sysmon Process Creation

A Sysmon Event ID 1 search for the investigated filename returned:

```text
20-09-2026 07:08:47 Process Create:...
```

The captured message did not expose the executable path, command line, parent process, process ID, or user context.

Therefore, the event establishes that a matching process-creation record was returned by the search, but the available evidence is insufficient to reconstruct the execution chain.

## Sysmon Network Activity

Sysmon Event ID 3 returned multiple events between approximately:

```text
07:03 and 07:25
```

The captured messages were displayed only as:

```text
Network connection detected:...
```

Because source/destination and process attribution were not visible in the extracted output, the observed connections cannot be directly attributed to `notepad.exe`.

## Wazuh Evidence

A Wazuh event was observed in the captured telemetry with:

```text
index        : wazuh-alerts-4.x-2026.09.17
agent.id     : 001
agent.name   : DESKTOP-9MMM37V
image        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
processId    : 20288
creation time: 2026-09-17 01:32:50.116 UTC
```

The event related to registry monitoring at:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-51198790-337801975-3228388354-1001
```

The captured evidence does not establish a relationship between this PowerShell event and `notepad.exe`.

## Evidence Correlation

| Evidence | Observation | Assessment |
|---|---|---|
| File path | System32 `notepad.exe` | Expected Windows location |
| File size | 360448 bytes | Recorded for identification |
| SHA256 | 468FFE...684577E | Exact file identifier |
| Version metadata | Microsoft Windows / Microsoft Corporation | Consistent with system component |
| Signature | Valid | Supports publisher authenticity |
| Signer | Microsoft Windows | Consistent with Windows component |
| Architecture | x64 | PE structure identified |
| ADS | Normal `:$DATA` only | No Zone.Identifier observed |
| Sysmon EID 1 | Matching event at 07:08:47 | Execution-related telemetry observed |
| Sysmon EID 3 | Multiple network events | Supporting telemetry only |
| Wazuh | PowerShell registry event | No established link to PE |

