# Investigation Timeline

| Time | Evidence | Description |
|---|---|---|
| 09-09-2026 09:56:13 | File metadata | `notepad.exe` creation time recorded |
| 09-09-2026 09:56:13 | File metadata | `notepad.exe` last-write time recorded |
| 17-09-2026 12:58:09 | File metadata | `notepad.exe` last-access time recorded |
| 20-09-2026 07:08:47 | Sysmon EID 1 | Matching process-creation event returned for `notepad.exe` |
| 20-09-2026 07:09:35 | Sysmon EID 3 | Network connection event observed |
| 20-09-2026 07:12:10 | Sysmon EID 3 | Multiple network connection events observed |
| 20-09-2026 07:12:31.731 | Wazuh | Registry monitoring event observed |
| 20-09-2026 07:12:39 | Sysmon EID 3 | Multiple network connection events observed |
| 20-09-2026 07:14:12 | Sysmon EID 3 | Network connection event observed |
| 20-09-2026 07:16:21 | Sysmon EID 3 | Multiple network connection events observed |
| 20-09-2026 07:18:24 | Sysmon EID 3 | Network connection event observed |
| 20-09-2026 07:20:34 | Sysmon EID 3 | Multiple network connection events observed |
| 20-09-2026 07:23:10 | Sysmon EID 3 | Network connection event observed |
| 20-09-2026 07:25:12 | Sysmon EID 3 | Multiple network connection events observed |
| 20-09-2026 07:25:13 | Sysmon EID 3 | Network connection event observed |

## Static Evidence

The investigated PE was:

```text
C:\Windows\System32\notepad.exe
```

SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

Architecture:

```text
x64
```

Signature:

```text
Valid
```

## Timeline Assessment

The timeline establishes that the file existed with recorded filesystem metadata and that Sysmon returned a matching process-creation event on 20-09-2026 at 07:08:47.

Additional Sysmon network events occurred across the following minutes. However, the captured event messages did not expose enough process and network fields to attribute those connections specifically to `notepad.exe`.

A Wazuh registry-monitoring event was also observed at 07:12:31.731, but no direct relationship to the investigated PE was established.

The timeline therefore provides chronological context without assigning unsupported causality between the events.
