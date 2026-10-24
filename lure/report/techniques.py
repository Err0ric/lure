"""Names for the MITRE ATLAS and ATT&CK IDs the attack library uses.

Verified on atlas.mitre.org and attack.mitre.org on 2026-10-23. An ID that
is not listed here shows as its bare ID in the report; add it here after
checking it.
"""

ATLAS = {
    "AML.T0048.000": "External Harms: Financial Harm",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0069.002": "Discover LLM System Information: System Prompt",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0080.001": "AI Agent Context Poisoning: Thread",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
}

ATTACK = {
    "T1005": "Data from Local System",
    "T1027": "Obfuscated Files or Information",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1485": "Data Destruction",
    "T1566": "Phishing",
    "T1656": "Impersonation",
    "T1657": "Financial Theft",
}

CATEGORIES = {
    "indirect_prompt_injection": "Indirect prompt injection",
    "direct_prompt_injection": "Direct prompt injection",
    "jailbreak": "Jailbreak",
    "data_leakage": "Data leakage",
    "tool_abuse": "Tool abuse",
}


def atlas_name(technique: str) -> str:
    return ATLAS.get(technique, technique)


def category_name(category: str) -> str:
    return CATEGORIES.get(category, category.replace("_", " ").capitalize())
