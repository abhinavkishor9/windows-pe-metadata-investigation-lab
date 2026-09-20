# windows-pe-metadata-investigation-lab
## Overview
A Portable Executable (PE) file is the Windows executable format used by files such as .exe, .dll, .sys, and related binaries.

PE metadata can provide useful investigative context before executing or reverse-engineering a file. The goal is to establish what the file claims to be, where it came from, whether it is signed, what version it identifies itself as, and whether its metadata contains anomalies.

Important PE metadata includes:

File name and path
File size
SHA256 hash
File creation/modification/access timestamps
File version and product information
Company and copyright information
Original filename
Digital signature information
PE architecture such as x86/x64
PE compilation timestamp, where available
Section information
Entry point and image characteristics
Import information, when a PE parsing utility is available
Evidence principle

PE metadata is context, not proof of maliciousness.

For example:

Unsigned executable
        ≠
Malware

Likewise:

Recent file timestamp
        ≠
Recent compilation

The investigation should correlate metadata with hashes, signatures, file location, process execution, Sysmon, and Wazuh.


This lab performs static triage of a Windows Portable Executable (PE) file without executing it intentionally. The investigation focuses on collecting file metadata, cryptographic hashes, version information, digital-signature details, PE architecture, alternate data streams, and available runtime telemetry.

The investigated file was:

`C:\Windows\System32\notepad.exe`

The investigation also reviewed Sysmon Event IDs 1 and 3 and available Wazuh telemetry to determine whether the file had execution or network-related evidence associated with it.

## Lab Objectives

- Establish a controlled baseline for examining a Windows PE file without intentionally executing it.
- Identify the exact file path and collect relevant filesystem metadata.
- Generate multiple cryptographic hashes to uniquely identify the examined binary.
- Extract embedded version-resource information and assess internal consistency.
- Examine Authenticode signature and certificate details associated with the file.
- Determine the executable architecture directly from the PE header.
- Inspect alternate data streams for additional file-origin context.
- Review PE structural information such as sections, entry point, and imported functions where available.
- Compare static PE characteristics with the expected location and role of the file.
- Investigate Sysmon process-creation telemetry associated with the examined executable.
- Review Sysmon network telemetry for supporting execution context.
- Examine relevant Wazuh alerts and archived telemetry associated with the file.
- Correlate static metadata with available runtime and security evidence.
- Identify gaps or limitations in the collected telemetry.
- Practice distinguishing observable PE characteristics from conclusions about malicious behavior.

## Lab Scenario

A Windows executable is identified during routine endpoint monitoring and requires initial static investigation before any further analysis or execution. The analyst must determine what the file is, how it identifies itself, whether its metadata is consistent with its expected Windows location, and whether available endpoint telemetry provides any additional context.

The investigation is performed on the identified PE file while avoiding intentional execution.

The analyst will:

- Collect filesystem metadata and cryptographic hashes.
- Examine version information, publisher details, and digital-signature status.
- Determine the PE architecture and review available structural information.
- Check alternate data streams for additional file-origin context.
- Review Sysmon process and network telemetry related to the file.
- Examine Wazuh alerts and archived events for supporting evidence.
- Correlate static and runtime observations without treating individual indicators as proof of malicious activity.

The final assessment should document what the available evidence establishes, what remains unknown, and any telemetry limitations encountered during the investigation.

## Environment

- Windows endpoint
- PowerShell 7.x
- Sysmon
- Wazuh
- Investigated file: `C:\Windows\System32\notepad.exe`

## Investigation Summary

The investigated file was present at the expected Windows system path and had a size of `360448` bytes.

The SHA256 hash was:

`468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E`

The file reported Microsoft Windows version metadata and a Microsoft Corporation publisher identity. Authenticode verification returned `Valid`, with the signer certificate showing `CN=Microsoft Windows, O=Microsoft Corporation`.

The PE-header inspection identified the file as x64.

A Sysmon Event ID 1 search returned a matching process-creation event at `20-09-2026 07:08:47`, but the available message only exposed `Process Create:...`, so the exact command line, parent process, process ID, and execution context could not be established from the captured output.

Sysmon Event ID 3 also returned multiple network events, but the available output exposed only `Network connection detected:...`. No direct attribution of those connections to `notepad.exe` could therefore be established from the collected text.

A Wazuh event showing PowerShell-related registry monitoring was also observed, but the available evidence did not establish a relationship between that event and the investigated PE.

## Assessment

The collected metadata is consistent with a Microsoft Windows system executable, including a valid Authenticode signature and Microsoft version information.

The available evidence does not establish malicious PE behavior.

The Sysmon and Wazuh outputs provide supporting telemetry but are too limited in the captured form to establish detailed process or network attribution.

The investigation therefore remains a **metadata-based assessment with limited runtime attribution**, rather than a malware determination.

## Key Evidence

| Evidence | Finding |
|---|---|
| File path | `C:\Windows\System32\notepad.exe` |
| File size | `360448` bytes |
| SHA256 | `468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E` |
| MD5 | `8A1D8175CCCA97054CDB25ACBB4CC07E` |
| SHA1 | `76CD26B59923157E09D2BC927BA8FB059F3155DC` |
| Architecture | x64 |
| Signature status | Valid |
| Signer | Microsoft Windows / Microsoft Corporation |
| Sysmon EID 1 | Matching event observed at 07:08:47 |
| Sysmon EID 3 | Multiple network events observed |
| Wazuh | PowerShell-related registry monitoring observed |
| Final assessment | No malicious behavior established from collected evidence |

## MITRE ATT&CK

- **T1059.001 – Command and Scripting Interpreter: PowerShell**
  - PowerShell is used to execute the controlled command.

- **T1027 – Obfuscated/Compressed Files and Information**
  - `-EncodedCommand` is used to execute a Base64-encoded PowerShell command.
