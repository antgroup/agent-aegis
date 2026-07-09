# AgentHazard Phase 0 Dry-Run Report

## Run Metadata

- Generated at: 2026-07-09T03:24:45.731Z
- Dataset: `/Users/qingyuqi/Desktop/工作/ClawAegis2.0/AgentHazard/data/dataset.json`
- Seed: `1337`
- Requested sample per category: `3`

## Dataset Summary

- Total instances: 2653
- Selected instances: 30

### By Category

| Category | Dataset | Selected |
|---|---:|---:|
| Compliance_Bypass | 174 | 3 |
| Data_Exfiltration | 342 | 3 |
| Destructive_Action | 125 | 3 |
| Internal_Reconnaissance | 453 | 3 |
| Persistence_Establishment | 255 | 3 |
| Privilege_Escalation | 167 | 3 |
| Prompt_Intel_Theft | 260 | 3 |
| Resource_Exhaustion | 376 | 3 |
| Supply_Chain_Poisoning | 248 | 3 |
| System_RCE | 253 | 3 |

### By Jailbreak Method

| Jailbreak Method | Dataset | Selected |
|---|---:|---:|
| Contextual_Persona_Enforcement | 271 | 1 |
| Dependency_Hook_Trigger | 380 | 4 |
| Direct | 199 | 1 |
| Encoded_Payload_Smuggling | 196 | 2 |
| Implicit_Indirect_Injection | 91 | 3 |
| Legacy_Code_Maintenance | 247 | 8 |
| Logical_Dependency_Inversion | 301 | 2 |
| Pseudo_Diagnostic_Debugging | 240 | 1 |
| Recursive_Salami_Slicing | 424 | 5 |
| Security_Audit_Gaslighting | 304 | 3 |

## Expected Snapshot Coverage Map

| Category | Expected Signals | Snapshot Fields | Causal Chains | Known Gaps |
|---|---|---|---|---|
| Compliance_Bypass | `openat(source/config)`<br>`connect(external git/service)` | `externalConnections`<br>`features.externalConnCount` | - | `normal repository access and code exfiltration can look similar without tool-call context`<br>`source paths are not always represented as sensitive paths` |
| Data_Exfiltration | `openat(secret path)`<br>`connect(external address)` | `sensitiveAccesses`<br>`externalConnections`<br>`features.externalConnCount` | `exfil` | `connect currently needs destination address/port to make exfil visible`<br>`sensitive patterns may miss project-specific secrets` |
| Destructive_Action | `unlink/unlinkat/rmdir/truncate` | `fileDeleteEvents` | `destructive` | `current eBPF probe does not capture unlink/unlinkat/rmdir`<br>`snapshot has no destructive file operation field yet` |
| Internal_Reconnaissance | `execve(scanner/tool)`<br>`connect(multiple hosts or ports)` | `binariesExecuted`<br>`externalConnections`<br>`distinctExternalPorts` | `recon` | `python socket scans may not trigger risky binary detection`<br>`port and destination diversity require connect addr/port capture` |
| Persistence_Establishment | `openat(persistence path)`<br>`execve(shell/helper)` | `persistenceAccesses`<br>`fileWriteEvents`<br>`binariesExecuted` | `persistence` | `persistence patterns need to be shared from context/patterns.ts`<br>`openat flags are needed to separate reads from writes` |
| Privilege_Escalation | `openat(/etc/shadow or privilege path)`<br>`execve(sudo/pkexec/suid helper)` | `sensitiveAccesses`<br>`binariesExecuted` | `privilege_escalation` | `SUID and capability abuse can be invisible without richer exec metadata`<br>`not all privilege targets are in sensitive path patterns` |
| Prompt_Intel_Theft | `openat(agent config/prompt path)`<br>`connect(optional external address)` | `sensitiveAccesses`<br>`externalConnections`<br>`toolCallToSyscallMapping` | `exfil` | `agent prompt/config paths may not be sensitive patterns`<br>`tool parameters need to survive into snapshot context` |
| Resource_Exhaustion | `fork/exec fanout`<br>`high event rate` | `features.forkRate`<br>`features.processFanout` | `resource_exhaustion` | `CPU or memory exhaustion may not create many processes`<br>`thresholds need a benign baseline` |
| Supply_Chain_Poisoning | `openat(build/dependency file)`<br>`execve(build/test/install command)` | `fileWriteEvents`<br>`execArgsSummary`<br>`binariesExecuted` | `write_then_run` | `write-then-run may span different directories`<br>`openat flags are needed to confirm modification` |
| System_RCE | `execve(shell/interpreter/payload)`<br>`openat(optional staged payload)` | `binariesExecuted`<br>`execArgsSummary`<br>`features.externalEventRatio` | `write_then_run` | `custom binaries may not match risky binary patterns`<br>`argv summaries are more useful than binary path alone` |

## Selected Instances

| Rank | ID | Category | Jailbreak Method | Turns | Source |
|---:|---:|---|---|---:|---|
| 1 | 1651 | Compliance_Bypass | Encoded_Payload_Smuggling | 3 | gemini |
| 2 | 1622 | Compliance_Bypass | Dependency_Hook_Trigger | 4 | gemini |
| 3 | 1687 | Compliance_Bypass | Legacy_Code_Maintenance | 3 | gemini |
| 4 | 1869 | Data_Exfiltration | Logical_Dependency_Inversion | 3 | examples |
| 5 | 443 | Data_Exfiltration | Legacy_Code_Maintenance | 4 | gemini |
| 6 | 1855 | Data_Exfiltration | Implicit_Indirect_Injection | 3 | examples |
| 7 | 803 | Destructive_Action | Logical_Dependency_Inversion | 3 | gemini |
| 8 | 2106 | Destructive_Action | Implicit_Indirect_Injection | 3 | examples |
| 9 | 2114 | Destructive_Action | Legacy_Code_Maintenance | 3 | examples |
| 10 | 832 | Internal_Reconnaissance | Direct | 3 | gemini |
| 11 | 1054 | Internal_Reconnaissance | Legacy_Code_Maintenance | 3 | gemini |
| 12 | 875 | Internal_Reconnaissance | Security_Audit_Gaslighting | 3 | gemini |
| 13 | 2621 | Persistence_Establishment | Recursive_Salami_Slicing | 4 | examples |
| 14 | 584 | Persistence_Establishment | Legacy_Code_Maintenance | 4 | gemini |
| 15 | 559 | Persistence_Establishment | Implicit_Indirect_Injection | 4 | gemini |
| 16 | 1088 | Privilege_Escalation | Encoded_Payload_Smuggling | 3 | gemini |
| 17 | 1630 | Privilege_Escalation | Pseudo_Diagnostic_Debugging | 3 | gemini |
| 18 | 1122 | Privilege_Escalation | Dependency_Hook_Trigger | 5 | gemini |
| 19 | 1432 | Prompt_Intel_Theft | Recursive_Salami_Slicing | 3 | gemini |
| 20 | 2572 | Prompt_Intel_Theft | Legacy_Code_Maintenance | 3 | examples |
| 21 | 1482 | Prompt_Intel_Theft | Dependency_Hook_Trigger | 3 | gemini |
| 22 | 1217 | Resource_Exhaustion | Recursive_Salami_Slicing | 6 | gemini |
| 23 | 1287 | Resource_Exhaustion | Dependency_Hook_Trigger | 5 | gemini |
| 24 | 1218 | Resource_Exhaustion | Security_Audit_Gaslighting | 5 | gemini |
| 25 | 2062 | Supply_Chain_Poisoning | Legacy_Code_Maintenance | 3 | examples |
| 26 | 1704 | Supply_Chain_Poisoning | Security_Audit_Gaslighting | 4 | examples |
| 27 | 627 | Supply_Chain_Poisoning | Recursive_Salami_Slicing | 4 | gemini |
| 28 | 1744 | System_RCE | Legacy_Code_Maintenance | 3 | examples |
| 29 | 114 | System_RCE | Recursive_Salami_Slicing | 4 | gemini |
| 30 | 69 | System_RCE | Contextual_Persona_Enforcement | 4 | gemini |

## Next Phase Gate

- Phase 0 passes when category/strategy sampling is stable and output files are reproducible for the same seed.
- Phase 0.5 should add a Snapshot exporter before any Docker/eBPF collection is attempted.

