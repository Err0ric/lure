# ATLAS and ATT&CK mapping

Every attack names the MITRE ATLAS techniques (`atlas:`, required) and ATT&CK techniques (`attack:`, may be empty) it exercises. Every result, report row, Markdown finding and SARIF rule carries the same IDs, copied from the attack file.

All IDs below were checked on https://atlas.mitre.org/ and https://attack.mitre.org/ on 2026-10-23. ATLAS adds agent techniques often: re-check before publishing results, and when adding an ID.

## How mapping works

| Piece | Where | Rule |
| --- | --- | --- |
| IDs on an attack | `atlas:` and `attack:` in `attacks/<category>/<id>.yaml` | The loader checks the format: `AML.T0000` or `AML.T0000.000`, and `T0000` or `T0000.000` |
| Technique names | `lure/report/techniques.py` | An ID not listed there shows as its bare ID in reports; add it after checking it |
| Report | ATLAS heatmap, findings grouped by technique (HTML and Markdown) | An attack mapped to two techniques counts under both |
| SARIF | Rule `properties.tags`, `properties.atlas`, `properties.attack` | One rule per attack id |

Map what the attack *exercises*, not everything it could lead to. Typical pattern: the delivery technique (direct or indirect prompt injection, jailbreak), plus the harm the `fail_if` rules catch (exfiltration via tool, data destruction via tool, financial harm), plus any evasion the payload uses (obfuscation).

## ATLAS techniques in the library

| ID | Name | Attacks |
| --- | --- | --- |
| AML.T0048.000 | External Harms: Financial Harm | lure-mem-002, lure-tab-001, lure-tpo-003 |
| AML.T0051.000 | LLM Prompt Injection: Direct | lure-dpi-001, lure-dpi-002, lure-dpi-003, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-jbk-003 |
| AML.T0051.001 | LLM Prompt Injection: Indirect | lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-008, lure-mem-001, lure-mem-003, lure-tab-001, lure-tab-002, lure-tab-003 |
| AML.T0053 | AI Agent Tool Invocation | lure-mem-002, lure-tab-001, lure-tab-002, lure-tab-003, lure-tpo-003 |
| AML.T0054 | LLM Jailbreak | lure-dpi-003, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-jbk-003 |
| AML.T0056 | Extract LLM System Prompt | lure-dpi-001, lure-jbk-003 |
| AML.T0057 | LLM Data Leakage | lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-ipi-008 |
| AML.T0068 | LLM Prompt Obfuscation | lure-ipi-004, lure-jbk-003 |
| AML.T0069.002 | Discover LLM System Information: System Prompt | lure-dpi-001 |
| AML.T0080.000 | AI Agent Context Poisoning: Memory | lure-mem-002, lure-mem-003 |
| AML.T0080.001 | AI Agent Context Poisoning: Thread | lure-ipi-007 v2, lure-mem-001 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-dpi-002, lure-dpi-003, lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-008, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-mem-001, lure-mem-003, lure-tab-003, lure-tpo-001, lure-tpo-002 |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | lure-tab-002 |
| AML.T0110.000 | AI Agent Tool Poisoning: Definition and Instructions | lure-tpo-001, lure-tpo-002, lure-tpo-003 |

## ATT&CK techniques in the library

| ID | Name | Attacks |
| --- | --- | --- |
| T1005 | Data from Local System | lure-dlk-003, lure-tab-003 |
| T1027 | Obfuscated Files or Information | lure-ipi-004 |
| T1048 | Exfiltration Over Alternative Protocol | lure-dlk-001, lure-dlk-002, lure-dlk-003, lure-dpi-002, lure-dpi-003, lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-008, lure-jbk-001, lure-jbk-002 v1, lure-jbk-002 v2, lure-mem-001, lure-mem-003, lure-tab-003, lure-tpo-001 |
| T1485 | Data Destruction | lure-tab-002 |
| T1566 | Phishing | lure-ipi-001, lure-ipi-002, lure-ipi-003, lure-ipi-004, lure-ipi-005, lure-ipi-006, lure-ipi-007 v1, lure-ipi-007 v2, lure-ipi-008 |
| T1567 | Exfiltration Over Web Service | lure-tpo-002 |
| T1656 | Impersonation | lure-ipi-005 |
| T1657 | Financial Theft | lure-mem-002, lure-tab-001, lure-tpo-003 |

## By attack

| Attack | Category | Severity | ATLAS | ATT&CK |
| --- | --- | --- | --- | --- |
| [lure-dlk-001](../attacks/data_leakage/lure-dlk-001.yaml) | Data leakage | high | AML.T0057, AML.T0051.001, AML.T0086 | T1048 |
| [lure-dlk-002](../attacks/data_leakage/lure-dlk-002.yaml) | Data leakage | medium | AML.T0057, AML.T0051.001, AML.T0086 | T1048 |
| [lure-dlk-003](../attacks/data_leakage/lure-dlk-003.yaml) | Data leakage | high | AML.T0057, AML.T0051.001, AML.T0086 | T1005, T1048 |
| [lure-dpi-001](../attacks/direct_prompt_injection/lure-dpi-001.yaml) | Direct prompt injection | medium | AML.T0051.000, AML.T0056, AML.T0069.002 | none |
| [lure-dpi-002](../attacks/direct_prompt_injection/lure-dpi-002.yaml) | Direct prompt injection | high | AML.T0051.000, AML.T0086 | T1048 |
| [lure-dpi-003](../attacks/direct_prompt_injection/lure-dpi-003.yaml) | Direct prompt injection | critical | AML.T0051.000, AML.T0054, AML.T0086 | T1048 |
| [lure-ipi-001](../attacks/indirect_prompt_injection/lure-ipi-001.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-002](../attacks/indirect_prompt_injection/lure-ipi-002.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-003](../attacks/indirect_prompt_injection/lure-ipi-003.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-004](../attacks/indirect_prompt_injection/lure-ipi-004.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0068, AML.T0086 | T1566, T1027, T1048 |
| [lure-ipi-005](../attacks/indirect_prompt_injection/lure-ipi-005.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1656, T1048 |
| [lure-ipi-006](../attacks/indirect_prompt_injection/lure-ipi-006.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-007 v1](../attacks/indirect_prompt_injection/lure-ipi-007-v1.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-007 v2](../attacks/indirect_prompt_injection/lure-ipi-007.yaml) | Indirect prompt injection | high | AML.T0051.001, AML.T0080.001, AML.T0086 | T1566, T1048 |
| [lure-ipi-008](../attacks/indirect_prompt_injection/lure-ipi-008.yaml) | Indirect prompt injection | critical | AML.T0051.001, AML.T0057, AML.T0086 | T1566, T1048 |
| [lure-jbk-001](../attacks/jailbreak/lure-jbk-001.yaml) | Jailbreak | high | AML.T0054, AML.T0051.000, AML.T0086 | T1048 |
| [lure-jbk-002 v1](../attacks/jailbreak/lure-jbk-002-v1.yaml) | Jailbreak | critical | AML.T0054, AML.T0051.000, AML.T0086 | T1048 |
| [lure-jbk-002 v2](../attacks/jailbreak/lure-jbk-002.yaml) | Jailbreak | critical | AML.T0054, AML.T0051.000, AML.T0086 | T1048 |
| [lure-jbk-003](../attacks/jailbreak/lure-jbk-003.yaml) | Jailbreak | high | AML.T0054, AML.T0051.000, AML.T0068, AML.T0056 | none |
| [lure-mem-001](../attacks/memory_poisoning/lure-mem-001.yaml) | Memory poisoning | high | AML.T0051.001, AML.T0080.001, AML.T0086 | T1048 |
| [lure-mem-002](../attacks/memory_poisoning/lure-mem-002.yaml) | Memory poisoning | critical | AML.T0080.000, AML.T0053, AML.T0048.000 | T1657 |
| [lure-mem-003](../attacks/memory_poisoning/lure-mem-003.yaml) | Memory poisoning | high | AML.T0051.001, AML.T0080.000, AML.T0086 | T1048 |
| [lure-tab-001](../attacks/tool_abuse/lure-tab-001.yaml) | Tool abuse | critical | AML.T0051.001, AML.T0053, AML.T0048.000 | T1657 |
| [lure-tab-002](../attacks/tool_abuse/lure-tab-002.yaml) | Tool abuse | high | AML.T0051.001, AML.T0053, AML.T0101 | T1485 |
| [lure-tab-003](../attacks/tool_abuse/lure-tab-003.yaml) | Tool abuse | critical | AML.T0051.001, AML.T0086, AML.T0053 | T1005, T1048 |
| [lure-tpo-001](../attacks/tool_poisoning/lure-tpo-001.yaml) | Tool poisoning | high | AML.T0110.000, AML.T0086 | T1048 |
| [lure-tpo-002](../attacks/tool_poisoning/lure-tpo-002.yaml) | Tool poisoning | high | AML.T0110.000, AML.T0086 | T1567 |
| [lure-tpo-003](../attacks/tool_poisoning/lure-tpo-003.yaml) | Tool poisoning | critical | AML.T0110.000, AML.T0053, AML.T0048.000 | T1657 |

## Adding or changing an ID

1. Find the technique on https://atlas.mitre.org/ (or https://attack.mitre.org/) and confirm the ID and name are current.
2. Add it to the attack's `atlas:` or `attack:` list.
3. If it is new to the library, add its name to `ATLAS` or `ATTACK` in `lure/report/techniques.py` and update the check date there.
4. Add it to this page. `tests/test_atlas_mapping.py` fails if an ID used by an attack is missing here or from `techniques.py`.
5. If an ID is unsure, say so in the pull request; do not publish results with an unverified ID.
