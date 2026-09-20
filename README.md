# Windows PE Metadata Investigation Lab

## Overview

This lab performs static triage of a Windows Portable Executable (PE) file without executing it intentionally. The investigation focuses on collecting file metadata, cryptographic hashes, version information, digital-signature details, PE architecture, alternate data streams, and available runtime telemetry.

The investigated file was:

`C:\Windows\System32\notepad.exe`

The investigation also reviewed Sysmon Event IDs 1 and 3 and available Wazuh telemetry to determine whether the file had execution or network-related evidence associated with it.

## Lab Objectives

- Identify and preserve the exact PE file under investigation.
- Collect file size and filesystem timestamps.
- Calculate MD5, SHA1, and SHA256 hashes.
- Extract Windows version-resource metadata.
- Validate the file's Authenticode signature.
- Record signer certificate details.
- Determine the PE architecture from the PE header.
- Check for alternate data streams.
- Review Sysmon process-creation evidence related to the file.
- Review Sysmon network telemetry for supporting context.
- Compare static PE metadata with available Wazuh telemetry.
- Distinguish file presence from actual execution evidence.
- Document limitations where telemetry does not expose sufficient process or network detail.

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

## MITRE ATT&CK

- **T1059.001 – Command and Scripting Interpreter: PowerShell**
  - PowerShell is used to execute the controlled command.

- **T1027 – Obfuscated/Compressed Files and Information**
  - `-EncodedCommand` is used to execute a Base64-encoded PowerShell command.
    

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

## Evidence Principle

Metadata is supporting evidence, not proof of intent or maliciousness.

A valid signature does not guarantee that every execution context is safe, while an unsigned file does not automatically indicate malware.

The investigation therefore relies on correlation between static metadata, file location, execution evidence, network context, and security telemetry.
