"""Names for the MITRE ATLAS and ATT&CK IDs the attack library uses.

Verified on atlas.mitre.org and attack.mitre.org on 2026-10-23. IDs added
for credential access and covert egress (AML.T0055, AML.T0067, AML.T0077,
AML.T0083, AML.T0098) and the v1.6 families (AML.T0050, AML.T0081,
AML.T0094, AML.T0112.000) were checked on 2026-10-24 in MITRE's ATLAS data
release 2026.09 (mitre-atlas/atlas-data, dist/v6), and the ATT&CK ones on
attack.mitre.org. An ID that is not listed here shows as its bare ID in the
report; add it here after checking it.
"""

ATLAS = {
    "AML.T0048.000": "External Harms: Financial Harm",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0069.002": "Discover LLM System Information: System Prompt",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0080.001": "AI Agent Context Poisoning: Thread",
    "AML.T0083": "Credentials from AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0094": "Delay Execution of LLM Instructions",
    "AML.T0098": "AI Agent Tool Credential Harvesting",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
    "AML.T0110.000": "AI Agent Tool Poisoning: Definition and Instructions",
    "AML.T0112.000": "Machine Compromise: Local AI Agent",
}

ATTACK = {
    "T1005": "Data from Local System",
    "T1027": "Obfuscated Files or Information",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1070": "Indicator Removal",
    "T1105": "Ingress Tool Transfer",
    "T1485": "Data Destruction",
    "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
    "T1552": "Unsecured Credentials",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1566": "Phishing",
    "T1567": "Exfiltration Over Web Service",
    "T1656": "Impersonation",
    "T1657": "Financial Theft",
    "T1677": "Poisoned Pipeline Execution",
}

CATEGORIES = {
    "indirect_prompt_injection": "Indirect prompt injection",
    "direct_prompt_injection": "Direct prompt injection",
    "jailbreak": "Jailbreak",
    "memory_poisoning": "Memory poisoning",
    "data_leakage": "Data leakage",
    "tool_abuse": "Tool abuse",
    "tool_poisoning": "Tool poisoning",
    "credential_access": "Credential access",
    "covert_egress": "Covert egress",
    "shell_execution": "Shell and code execution",
    "self_modification": "Self-modification",
    "persistence": "Persistence",
}


def atlas_name(technique: str) -> str:
    return ATLAS.get(technique, technique)


def category_name(category: str) -> str:
    return CATEGORIES.get(category, category.replace("_", " ").capitalize())
