# ATLAS and ATT&CK mapping

Every attack names the MITRE ATLAS techniques (`atlas:`, required) and ATT&CK techniques (`attack:`, may be empty) it exercises. Every result, report row, Markdown finding and SARIF rule carries the same IDs, copied from the attack file.

All IDs below were checked on https://atlas.mitre.org/ and https://attack.mitre.org/ on 2026-10-23. IDs first used by the credential access and covert egress attacks (AML.T0055, AML.T0067, AML.T0077, AML.T0083, AML.T0098) were checked on 2026-10-24 in MITRE's ATLAS data release 2026.09 ([mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data), `dist/v6/ATLAS-2026.09.yaml`), and T1552, T1552.001 and T1552.005 on attack.mitre.org. The v1.7 scenario packs added AML.T0012 Valid Accounts and AML.T0073 Impersonation (ATLAS 2026.09) and T1098 and T1098.007 (attack.mitre.org, 2026-10-25). ATLAS adds agent techniques often: re-check before publishing results, and when adding an ID.

## How mapping works

| Piece | Where | Rule |
| --- | --- | --- |
| IDs on an attack | `atlas:` and `attack:` in `attacks/<category>/<id>.yaml` | The loader checks the format: `AML.T0000` or `AML.T0000.000`, and `T0000` or `T0000.000` |
| Technique names | `lure/report/techniques.py` | An ID not listed there shows as its bare ID in reports; add it after checking it |
| Report | ATLAS heatmap, findings grouped by technique (HTML and Markdown) | An attack mapped to two techniques counts under both |
| SARIF | Rule `properties.tags`, `properties.atlas`, `properties.attack` | One rule per attack id |

| Payload variants | `variant` in each result (`lure run --variants`) | A variant keeps its attack's IDs. An `encoded` variant (base64, rot13, hex) also adds AML.T0068 LLM Prompt Obfuscation, verified 2026-10-24; `rephrased`, `split` and `buried` add nothing |

Map what the attack *exercises*, not everything it could lead to. Typical pattern: the delivery technique (direct or indirect prompt injection, jailbreak), plus the harm the `fail_if` rules catch (exfiltration via tool, data destruction via tool, financial harm), plus any evasion the payload uses (obfuscation).

## ATLAS techniques in the library

| ID | Name | Attacks |
| --- | --- | --- |
| AML.T0012 | Valid Accounts | lure-cra-006 |
| AML.T0048.000 | External Harms: Financial Harm | lure-mem-002 v1, lure-mem-002 v2, lure-mem-004, lure-mem-005, lure-tab-001, lure-tpo-003 |
| AML.T0050 | Command and Scripting Interpreter | lure-shx-001, lure-shx-002, lure-shx-003 |
| AML.T0051.000 | LLM Prompt Injection: Direct | lure-dpi-001, lure-dpi-002, lure-dpi-003, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-jbk-003 |
| AML.T0051.001 | LLM Prompt Injection: Indirect | lure-cra-001, lure-cra-002, lure-cra-003, lure-cra-004, lure-cra-005, lure-cra-006, lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-egr-001, lure-egr-002, lure-egr-003, lure-egr-004, lure-egr-005, lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-007 v3, lure-ipi-007 v4, lure-ipi-008, lure-ipi-009, lure-ipi-010, lure-ipi-011, lure-ipi-012, lure-ipi-013, lure-mem-001, lure-mem-003, lure-mem-004, lure-per-001, lure-per-002, lure-per-003, lure-shx-001, lure-shx-002, lure-shx-003, lure-smo-001, lure-smo-002, lure-smo-003, lure-tab-001, lure-tab-002, lure-tab-003 |
| AML.T0053 | AI Agent Tool Invocation | lure-cra-003, lure-cra-006, lure-ipi-011, lure-ipi-012, lure-ipi-013, lure-mem-002 v1, lure-mem-002 v2, lure-mem-004, lure-mem-005, lure-per-001, lure-per-002, lure-per-003, lure-shx-001, lure-shx-002, lure-shx-003, lure-smo-001, lure-smo-002, lure-smo-003, lure-tab-001, lure-tab-002, lure-tab-003, lure-tpo-003 |
| AML.T0054 | LLM Jailbreak | lure-dpi-003, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-jbk-003 |
| AML.T0055 | Unsecured Credentials | lure-cra-001, lure-cra-002, lure-cra-003, lure-cra-005 |
| AML.T0056 | Extract LLM System Prompt | lure-dpi-001, lure-jbk-003 |
| AML.T0057 | LLM Data Leakage | lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-egr-001, lure-egr-002, lure-ipi-008 |
| AML.T0067 | LLM Trusted Output Components Manipulation | lure-egr-002 |
| AML.T0068 | LLM Prompt Obfuscation | lure-ipi-004, lure-jbk-003; every `encoded` variant |
| AML.T0069.002 | Discover LLM System Information: System Prompt | lure-dpi-001 |
| AML.T0073 | Impersonation | lure-cra-006, lure-ipi-011, lure-ipi-012, lure-ipi-013 |
| AML.T0077 | LLM Response Rendering | lure-egr-001, lure-egr-002, lure-egr-003, lure-egr-004, lure-egr-005 |
| AML.T0080.000 | AI Agent Context Poisoning: Memory | lure-mem-002 v1, lure-mem-002 v2, lure-mem-003, lure-mem-004, lure-mem-005 |
| AML.T0080.001 | AI Agent Context Poisoning: Thread | lure-ipi-007 v2, lure-ipi-007 v3, lure-ipi-007 v4, lure-mem-001 |
| AML.T0081 | Modify AI Agent Configuration | lure-smo-001, lure-smo-002, lure-smo-003 |
| AML.T0083 | Credentials from AI Agent Configuration | lure-cra-004 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | lure-cra-001, lure-cra-002, lure-cra-003, lure-cra-004, lure-cra-005, lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-dpi-002, lure-dpi-003, lure-egr-003, lure-egr-004, lure-egr-005, lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-007 v3, lure-ipi-007 v4, lure-ipi-008, lure-ipi-009, lure-ipi-010, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-mem-001, lure-mem-003, lure-shx-002, lure-shx-003, lure-tab-003, lure-tpo-001, lure-tpo-002, lure-tpo-004 |
| AML.T0094 | Delay Execution of LLM Instructions | lure-per-003 |
| AML.T0098 | AI Agent Tool Credential Harvesting | lure-cra-001, lure-cra-002, lure-cra-003, lure-cra-004, lure-cra-005 |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | lure-tab-002 |
| AML.T0110.000 | AI Agent Tool Poisoning: Definition and Instructions | lure-tpo-001, lure-tpo-002, lure-tpo-003, lure-tpo-004 |
| AML.T0112.000 | Machine Compromise: Local AI Agent | lure-per-001, lure-per-002 |

## ATT&CK techniques in the library

| ID | Name | Attacks |
| --- | --- | --- |
| T1005 | Data from Local System | lure-dlk-003, lure-tab-003 |
| T1027 | Obfuscated Files or Information | lure-ipi-004 |
| T1048 | Exfiltration Over Alternative Protocol | lure-cra-001, lure-cra-002, lure-cra-003, lure-cra-004, lure-cra-005, lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-dpi-002, lure-dpi-003, lure-egr-001, lure-egr-002, lure-egr-003, lure-egr-004, lure-egr-005, lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-007 v3, lure-ipi-007 v4, lure-ipi-008, lure-ipi-009, lure-ipi-010, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-mem-001, lure-mem-003, lure-shx-002, lure-shx-003, lure-tab-003, lure-tpo-001, lure-tpo-004 |
| T1053.003 | Scheduled Task/Job: Cron | lure-per-001 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | lure-shx-001, lure-shx-002, lure-shx-003 |
| T1070 | Indicator Removal | lure-smo-003 |
| T1098 | Account Manipulation | lure-cra-006, lure-ipi-012 |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | lure-ipi-013 |
| T1105 | Ingress Tool Transfer | lure-shx-001 |
| T1485 | Data Destruction | lure-tab-002 |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | lure-per-002 |
| T1552 | Unsecured Credentials | lure-cra-002, lure-cra-005 |
| T1552.001 | Unsecured Credentials: Credentials In Files | lure-cra-001, lure-cra-004 |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | lure-cra-003 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | lure-smo-001, lure-smo-002, lure-smo-003 |
| T1566 | Phishing | lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-007 v3, lure-ipi-007 v4, lure-ipi-008, lure-ipi-009 |
| T1567 | Exfiltration Over Web Service | lure-tpo-002 |
| T1656 | Impersonation | lure-cra-006, lure-ipi-005, lure-ipi-007 v3, lure-ipi-009, lure-ipi-011, lure-ipi-012, lure-ipi-013, lure-tpo-004 |
| T1657 | Financial Theft | lure-ipi-011, lure-mem-002 v1, lure-mem-002 v2, lure-mem-004, lure-mem-005, lure-tab-001, lure-tpo-003 |
| T1677 | Poisoned Pipeline Execution | lure-per-003 |

## By attack

| Attack | Category | Severity | ATLAS | ATT&CK |
| --- | --- | --- | --- | --- |
| [lure-cra-001](../attacks/credential_access/lure-cra-001.yaml) | Credential access | high | AML.T0051.001, AML.T0055, AML.T0098, AML.T0086 | T1552.001, T1048 |
| [lure-cra-002](../attacks/credential_access/lure-cra-002.yaml) | Credential access | high | AML.T0051.001, AML.T0055, AML.T0098, AML.T0086 | T1552, T1048 |
| [lure-cra-003](../attacks/credential_access/lure-cra-003.yaml) | Credential access | critical | AML.T0051.001, AML.T0053, AML.T0055, AML.T0098, AML.T0086 | T1552.005, T1048 |
| [lure-cra-004](../attacks/credential_access/lure-cra-004.yaml) | Credential access | high | AML.T0051.001, AML.T0083, AML.T0098, AML.T0086 | T1552.001, T1048 |
| [lure-cra-005](../attacks/credential_access/lure-cra-005.yaml) | Credential access | high | AML.T0051.001, AML.T0055, AML.T0098, AML.T0086 | T1552, T1048 |
| [lure-cra-006](../attacks/credential_access/lure-cra-006.yaml) | Credential access | critical | AML.T0051.001, AML.T0073, AML.T0012, AML.T0053 | T1098, T1656 |
| [lure-dlk-001](../attacks/data_leakage/lure-dlk-001.yaml) | Data leakage | high | AML.T0057, AML.T0051.001, AML.T0086 | T1048 |
| [lure-dlk-002](../attacks/data_leakage/lure-dlk-002.yaml) | Data leakage | medium | AML.T0057, AML.T0051.001, AML.T0086 | T1048 |
| [lure-dlk-003](../attacks/data_leakage/lure-dlk-003.yaml) | Data leakage | high | AML.T0057, AML.T0051.001, AML.T0086 | T1005, T1048 |
| [lure-dpi-001](../attacks/direct_prompt_injection/lure-dpi-001.yaml) | Direct prompt injection | medium | AML.T0051.000, AML.T0056, AML.T0069.002 | none |
| [lure-dpi-002](../attacks/direct_prompt_injection/lure-dpi-002.yaml) | Direct prompt injection | high | AML.T0051.000, AML.T0086 | T1048 |
| [lure-dpi-003](../attacks/direct_prompt_injection/lure-dpi-003.yaml) | Direct prompt injection | critical | AML.T0051.000, AML.T0054, AML.T0086 | T1048 |
| [lure-egr-001](../attacks/covert_egress/lure-egr-001.yaml) | Covert egress | high | AML.T0051.001, AML.T0077, AML.T0057 | T1048 |
| [lure-egr-002](../attacks/covert_egress/lure-egr-002.yaml) | Covert egress | medium | AML.T0051.001, AML.T0077, AML.T0067, AML.T0057 | T1048 |
| [lure-egr-003](../attacks/covert_egress/lure-egr-003.yaml) | Covert egress | high | AML.T0051.001, AML.T0077, AML.T0086 | T1048 |
| [lure-egr-004](../attacks/covert_egress/lure-egr-004.yaml) | Covert egress | high | AML.T0051.001, AML.T0077, AML.T0086 | T1048 |
| [lure-egr-005](../attacks/covert_egress/lure-egr-005.yaml) | Covert egress | high | AML.T0051.001, AML.T0077, AML.T0086 | T1048 |
| [lure-ipi-001](../attacks/indirect_prompt_injection/lure-ipi-001.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-002](../attacks/indirect_prompt_injection/lure-ipi-002.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-003](../attacks/indirect_prompt_injection/lure-ipi-003.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-004](../attacks/indirect_prompt_injection/lure-ipi-004.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0068, AML.T0086 | T1566, T1027, T1048 |
| [lure-ipi-005](../attacks/indirect_prompt_injection/lure-ipi-005.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1656, T1048 |
| [lure-ipi-006](../attacks/indirect_prompt_injection/lure-ipi-006.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-007 v1](../attacks/indirect_prompt_injection/lure-ipi-007-v1.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-007 v2](../attacks/indirect_prompt_injection/lure-ipi-007-v2.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0080.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-007 v3](../attacks/indirect_prompt_injection/lure-ipi-007-v3.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0080.001, AML.T0086 | T1566, T1656, T1048 |
| [lure-ipi-007 v4](../attacks/indirect_prompt_injection/lure-ipi-007.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0080.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-008](../attacks/indirect_prompt_injection/lure-ipi-008.yaml) | Indirect prompt injection | critical | AML.T0051.001, AML.T0057, AML.T0086 | T1566, T1048 |
| [lure-ipi-009](../attacks/indirect_prompt_injection/lure-ipi-009.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048, T1656 |
| [lure-ipi-010](../attacks/indirect_prompt_injection/lure-ipi-010.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1048 |
| [lure-ipi-011](../attacks/indirect_prompt_injection/lure-ipi-011.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0073, AML.T0053 | T1657, T1656 |
| [lure-ipi-012](../attacks/indirect_prompt_injection/lure-ipi-012.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0073, AML.T0053 | T1098, T1656 |
| [lure-ipi-013](../attacks/indirect_prompt_injection/lure-ipi-013.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0073, AML.T0053 | T1098.007, T1656 |
| [lure-jbk-001](../attacks/jailbreak/lure-jbk-001.yaml) | Jailbreak | high | AML.T0054, AML.T0051.000, AML.T0086 | T1048 |
| [lure-jbk-002 v1](../attacks/jailbreak/lure-jbk-002-v1.yaml) | Jailbreak | critical | AML.T0054, AML.T0051.000, AML.T0086 | T1048 |
| [lure-jbk-002 v2](../attacks/jailbreak/lure-jbk-002.yaml) | Jailbreak | critical | AML.T0054, AML.T0051.000, AML.T0086 | T1048 |
| [lure-jbk-003](../attacks/jailbreak/lure-jbk-003.yaml) | Jailbreak | high | AML.T0054, AML.T0051.000, AML.T0068, AML.T0056 | none |
| [lure-mem-001](../attacks/memory_poisoning/lure-mem-001.yaml) | Memory poisoning | high | AML.T0051.001, AML.T0080.001, AML.T0086 | T1048 |
| [lure-mem-002 v1](../attacks/memory_poisoning/lure-mem-002-v1.yaml) | Memory poisoning | critical | AML.T0080.000, AML.T0053, AML.T0048.000 | T1657 |
| [lure-mem-002 v2](../attacks/memory_poisoning/lure-mem-002.yaml) | Memory poisoning | critical | AML.T0080.000, AML.T0053, AML.T0048.000 | T1657 |
| [lure-mem-003](../attacks/memory_poisoning/lure-mem-003.yaml) | Memory poisoning | high | AML.T0051.001, AML.T0080.000, AML.T0086 | T1048 |
| [lure-mem-004](../attacks/memory_poisoning/lure-mem-004.yaml) | Memory poisoning | critical | AML.T0051.001, AML.T0080.000, AML.T0053, AML.T0048.000 | T1657 |
| [lure-mem-005](../attacks/memory_poisoning/lure-mem-005.yaml) | Memory poisoning | high | AML.T0080.000, AML.T0053, AML.T0048.000 | T1657 |
| [lure-per-001](../attacks/persistence/lure-per-001.yaml) | Persistence | critical | AML.T0051.001, AML.T0053, AML.T0112.000 | T1053.003 |
| [lure-per-002](../attacks/persistence/lure-per-002.yaml) | Persistence | critical | AML.T0051.001, AML.T0053, AML.T0112.000 | T1546.004 |
| [lure-per-003](../attacks/persistence/lure-per-003.yaml) | Persistence | critical | AML.T0051.001, AML.T0094, AML.T0053 | T1677 |
| [lure-shx-001](../attacks/shell_execution/lure-shx-001.yaml) | Shell and code execution | critical | AML.T0051.001, AML.T0053, AML.T0050 | T1059.004, T1105 |
| [lure-shx-002](../attacks/shell_execution/lure-shx-002.yaml) | Shell and code execution | high | AML.T0051.001, AML.T0050, AML.T0053, AML.T0086 | T1059.004, T1048 |
| [lure-shx-003](../attacks/shell_execution/lure-shx-003.yaml) | Shell and code execution | critical | AML.T0051.001, AML.T0050, AML.T0053, AML.T0086 | T1059.004, T1048 |
| [lure-smo-001](../attacks/self_modification/lure-smo-001.yaml) | Self-modification | high | AML.T0051.001, AML.T0081, AML.T0053 | T1562.001 |
| [lure-smo-002](../attacks/self_modification/lure-smo-002.yaml) | Self-modification | critical | AML.T0051.001, AML.T0081, AML.T0053 | T1562.001 |
| [lure-smo-003](../attacks/self_modification/lure-smo-003.yaml) | Self-modification | critical | AML.T0051.001, AML.T0081, AML.T0053 | T1562.001, T1070 |
| [lure-tab-001](../attacks/tool_abuse/lure-tab-001.yaml) | Tool abuse | critical | AML.T0051.001, AML.T0053, AML.T0048.000 | T1657 |
| [lure-tab-002](../attacks/tool_abuse/lure-tab-002.yaml) | Tool abuse | high | AML.T0051.001, AML.T0053, AML.T0101 | T1485 |
| [lure-tab-003](../attacks/tool_abuse/lure-tab-003.yaml) | Tool abuse | critical | AML.T0051.001, AML.T0086, AML.T0053 | T1005, T1048 |
| [lure-tpo-001](../attacks/tool_poisoning/lure-tpo-001.yaml) | Tool poisoning | high | AML.T0110.000, AML.T0086 | T1048 |
| [lure-tpo-002](../attacks/tool_poisoning/lure-tpo-002.yaml) | Tool poisoning | high | AML.T0110.000, AML.T0086 | T1567 |
| [lure-tpo-003](../attacks/tool_poisoning/lure-tpo-003.yaml) | Tool poisoning | critical | AML.T0110.000, AML.T0053, AML.T0048.000 | T1657 |
| [lure-tpo-004](../attacks/tool_poisoning/lure-tpo-004.yaml) | Tool poisoning | high | AML.T0110.000, AML.T0086 | T1048, T1656 |

## Arcanum Prompt Injection Taxonomy

Alongside ATLAS and ATT&CK, every current attack carries codes from the Arcanum Prompt Injection Taxonomy v1.6.1 (`arcanum:` in the attack file, `attack.arcanum` in results, tags on SARIF rules). Based on the Arcanum Prompt Injection Taxonomy by Jason Haddix, Arcanum Information Security (arcanum-sec.com). Lure is not affiliated with or endorsed by Arcanum Information Security; see [`THIRD_PARTY.md`](../THIRD_PARTY.md).

| Piece | Rule |
| --- | --- |
| Pillars | `input` (PIT-N), `intent` (PIT-I), `technique` (PIT-T), `evasion` (PIT-E); `input`, `intent` and `technique` are required on current attacks |
| Codes | Taken from the vendored `lure/arcanum/taxonomy.json`, never from memory. The loader rejects a code that is not in the taxonomy or is in another pillar |
| Intent | PIT-I-19 when the harm is data reaching an outsider; PIT-I-20 when the action itself is the harm (pay, delete) |
| Technique | PIT-T-60 for a plain ask; PIT-T-56 when the payload claims an approval or a sender |
| Variants | `split` adds PIT-T-24 (alias Payload Splitting); `encoded` adds PIT-E-07 (base64), PIT-E-14 (rot13) or PIT-E-21 (hex); `rephrased` and `buried` add nothing |
| ATLAS cross-check | `tests/test_arcanum.py` checks each attack's ATLAS IDs against the ATLAS IDs named in the taxonomy's aliases. Reviewed exceptions: AML.T0054 on the jailbreak attacks and `lure-dpi-003` (the jailbreak is the technique, not the intent), AML.T0053 on `lure-tab-003` (the harm is the data, not the tool call) |
| Pinned versions | Not mapped; they stay byte-identical |

Coverage of the taxonomy: [`arcanum-coverage.md`](arcanum-coverage.md), written by `lure coverage`.

## Adding or changing an ID

1. Find the technique on https://atlas.mitre.org/ (or https://attack.mitre.org/) and confirm the ID and name are current.
2. Add it to the attack's `atlas:` or `attack:` list.
3. If it is new to the library, add its name to `ATLAS` or `ATTACK` in `lure/report/techniques.py` and update the check date there.
4. Add it to this page. `tests/test_atlas_mapping.py` fails if an ID used by an attack is missing here or from `techniques.py`.
5. If an ID is unsure, say so in the pull request; do not publish results with an unverified ID.
