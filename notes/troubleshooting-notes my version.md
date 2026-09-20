# Troubleshooting Notes

## PE File Variable

The investigation depended on the `$PEFile` variable.

The variable was initialized as:

```powershell
$PEFile = "C:\Windows\System32\notepad.exe"
```

If `$PEFile` is not initialized, commands using `Get-Item`, `Get-FileHash`, or `Split-Path` may fail or produce incomplete results.

## Evidence Path Variables

The lab used:

```powershell
$LabPath = "C:\PEMetadataLab"
$EvidencePath = "$LabPath\Evidence"
$SamplePath = "$LabPath\Sample"
```

The directories were successfully created and verified with `Test-Path`.

## Step 7 — Architecture Tooling

The original approach used `dumpbin.exe`, but Visual Studio developer tools were not assumed to be installed.

A native PowerShell PE-header method was therefore used instead:

```powershell
$bytes = [System.IO.File]::ReadAllBytes($PEFile)
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)

switch ($machine) {
    0x014C { "Architecture: x86 (32-bit)" }
    0x8664 { "Architecture: x64 (64-bit)" }
    0xAA64 { "Architecture: ARM64" }
    default { "Architecture: Unknown (Machine: 0x{0:X4})" -f $machine }
}
```

This returned:

```text
Architecture: x64 (64-bit)
```

## Sysmon Event ID 1

The filename search returned a matching event, but the captured message was only:

```text
Process Create:...
```

Because the extracted output did not contain the detailed event fields, no assumptions were made about:

- Parent process
- Command line
- Process ID
- User
- Integrity level
- Hashes
- Execution chain

The event was therefore retained as limited supporting evidence.

## Sysmon Event ID 3

Multiple network events were returned, but the captured output only displayed:

```text
Network connection detected:...
```

The absence of visible source, destination, port, and process information prevented reliable attribution to `notepad.exe`.

These events were therefore not used as proof of network activity by the investigated executable.

## Alternate Data Streams

The ADS check showed only:

```text
:$DATA
```

No `Zone.Identifier` stream was observed.

The absence of this stream was not interpreted as proof that the file was never downloaded or transferred.

## Digital Signature Interpretation

The file returned:

```text
Status : Valid
```

This was treated as supporting publisher/authenticity evidence.

The investigation did not interpret the valid signature as proof that the executable could never be abused or replaced in another context.

## Wazuh Correlation

A PowerShell registry-monitoring event was observed in Wazuh.

Although the event was temporally relevant to the broader investigation, the captured evidence did not connect it to `notepad.exe`.

The event was therefore documented separately instead of being incorrectly classified as PE-related behavior.

