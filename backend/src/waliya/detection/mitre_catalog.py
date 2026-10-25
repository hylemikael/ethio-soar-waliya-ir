"""Local, offline, authoritative MITRE ATT&CK reference catalog.

Version: v15.1
Provides deterministic lookup of MITRE ATT&CK techniques, tactics,
and reference metadata without internet dependency or external LLM calls.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

MITRE_CATALOG_VERSION = "v15.1"


class CatalogTechniqueEntry(BaseModel):
    """Entry representing an authoritative MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactics: List[str]
    description: str
    reference_url: str
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None


# Authoritative local catalog for enterprise Linux and cross-platform techniques
MITRE_CATALOG: Dict[str, CatalogTechniqueEntry] = {
    # Execution
    "T1059": CatalogTechniqueEntry(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactics=["Execution"],
        description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        reference_url="https://attack.mitre.org/techniques/T1059/",
        is_subtechnique=False,
    ),
    "T1059.004": CatalogTechniqueEntry(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactics=["Execution"],
        description="Adversaries may abuse Unix shell interpreters to execute commands, scripts, or command line arguments.",
        reference_url="https://attack.mitre.org/techniques/T1059/004/",
        is_subtechnique=True,
        parent_technique_id="T1059",
    ),
    "T1204": CatalogTechniqueEntry(
        technique_id="T1204",
        name="User Execution",
        tactics=["Execution"],
        description="An adversary may rely upon specific actions by a user in order to gain execution.",
        reference_url="https://attack.mitre.org/techniques/T1204/",
        is_subtechnique=False,
    ),
    "T1053": CatalogTechniqueEntry(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactics=["Execution", "Persistence", "Privilege Escalation"],
        description="Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        reference_url="https://attack.mitre.org/techniques/T1053/",
        is_subtechnique=False,
    ),
    "T1053.003": CatalogTechniqueEntry(
        technique_id="T1053.003",
        name="Scheduled Task/Job: Cron",
        tactics=["Execution", "Persistence", "Privilege Escalation"],
        description="Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.",
        reference_url="https://attack.mitre.org/techniques/T1053/003/",
        is_subtechnique=True,
        parent_technique_id="T1053",
    ),

    # Persistence
    "T1505": CatalogTechniqueEntry(
        technique_id="T1505",
        name="Server Software Component",
        tactics=["Persistence"],
        description="Adversaries may abuse server software components to establish persistent access to systems.",
        reference_url="https://attack.mitre.org/techniques/T1505/",
        is_subtechnique=False,
    ),
    "T1505.003": CatalogTechniqueEntry(
        technique_id="T1505.003",
        name="Server Software Component: Web Shell",
        tactics=["Persistence"],
        description="Adversaries may backdoor web servers by installing web shells to maintain persistent web-based access.",
        reference_url="https://attack.mitre.org/techniques/T1505/003/",
        is_subtechnique=True,
        parent_technique_id="T1505",
    ),

    # Privilege Escalation & Defense Evasion
    "T1548": CatalogTechniqueEntry(
        technique_id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactics=["Privilege Escalation", "Defense Evasion"],
        description="Adversaries may circumvent mechanisms designed to control elevation of privileges.",
        reference_url="https://attack.mitre.org/techniques/T1548/",
        is_subtechnique=False,
    ),
    "T1548.003": CatalogTechniqueEntry(
        technique_id="T1548.003",
        name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        tactics=["Privilege Escalation", "Defense Evasion"],
        description="Adversaries may abuse sudo permissions and caching to elevate system privileges without credential prompting.",
        reference_url="https://attack.mitre.org/techniques/T1548/003/",
        is_subtechnique=True,
        parent_technique_id="T1548",
    ),
    "T1562": CatalogTechniqueEntry(
        technique_id="T1562",
        name="Impair Defenses",
        tactics=["Defense Evasion"],
        description="Adversaries may impair defenses to avoid detection or hinder defensive operations.",
        reference_url="https://attack.mitre.org/techniques/T1562/",
        is_subtechnique=False,
    ),
    "T1562.001": CatalogTechniqueEntry(
        technique_id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactics=["Defense Evasion"],
        description="Adversaries may disable or modify security tools to avoid detection.",
        reference_url="https://attack.mitre.org/techniques/T1562/001/",
        is_subtechnique=True,
        parent_technique_id="T1562",
    ),
    "T1070": CatalogTechniqueEntry(
        technique_id="T1070",
        name="Indicator Removal",
        tactics=["Defense Evasion"],
        description="Adversaries may delete or alter generated artifacts on a host system to hide activity.",
        reference_url="https://attack.mitre.org/techniques/T1070/",
        is_subtechnique=False,
    ),
    "T1070.004": CatalogTechniqueEntry(
        technique_id="T1070.004",
        name="Indicator Removal: File Deletion",
        tactics=["Defense Evasion"],
        description="Adversaries may delete files left behind by the actions of their software or tools to hinder forensic investigations.",
        reference_url="https://attack.mitre.org/techniques/T1070/004/",
        is_subtechnique=True,
        parent_technique_id="T1070",
    ),
    "T1027": CatalogTechniqueEntry(
        technique_id="T1027",
        name="Obfuscated/Compressed Files and Information",
        tactics=["Defense Evasion"],
        description="Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        reference_url="https://attack.mitre.org/techniques/T1027/",
        is_subtechnique=False,
    ),

    # Credential Access
    "T1110": CatalogTechniqueEntry(
        technique_id="T1110",
        name="Brute Force",
        tactics=["Credential Access"],
        description="Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        reference_url="https://attack.mitre.org/techniques/T1110/",
        is_subtechnique=False,
    ),
    "T1110.001": CatalogTechniqueEntry(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactics=["Credential Access"],
        description="Adversaries may systematically guess passwords to authenticate to valid accounts.",
        reference_url="https://attack.mitre.org/techniques/T1110/001/",
        is_subtechnique=True,
        parent_technique_id="T1110",
    ),
    "T1003": CatalogTechniqueEntry(
        technique_id="T1003",
        name="OS Credential Dumping",
        tactics=["Credential Access"],
        description="Adversaries may attempt to dump credentials to obtain account login and credential material.",
        reference_url="https://attack.mitre.org/techniques/T1003/",
        is_subtechnique=False,
    ),
    "T1003.008": CatalogTechniqueEntry(
        technique_id="T1003.008",
        name="OS Credential Dumping: /etc/passwd and /etc/shadow",
        tactics=["Credential Access"],
        description="Adversaries may obtain credentials by reading /etc/passwd or /etc/shadow files on Unix systems.",
        reference_url="https://attack.mitre.org/techniques/T1003/008/",
        is_subtechnique=True,
        parent_technique_id="T1003",
    ),

    # Discovery
    "T1046": CatalogTechniqueEntry(
        technique_id="T1046",
        name="Network Service Discovery",
        tactics=["Discovery"],
        description="Adversaries may attempt to get a listing of services running on hosts through port and service scanning.",
        reference_url="https://attack.mitre.org/techniques/T1046/",
        is_subtechnique=False,
    ),
    "T1082": CatalogTechniqueEntry(
        technique_id="T1082",
        name="System Information Discovery",
        tactics=["Discovery"],
        description="Adversaries may attempt to get detailed information about the operating system and hardware.",
        reference_url="https://attack.mitre.org/techniques/T1082/",
        is_subtechnique=False,
    ),
    "T1083": CatalogTechniqueEntry(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactics=["Discovery"],
        description="Adversaries may enumerate files and directories or search in specific locations.",
        reference_url="https://attack.mitre.org/techniques/T1083/",
        is_subtechnique=False,
    ),
    "T1033": CatalogTechniqueEntry(
        technique_id="T1033",
        name="System Owner/User Discovery",
        tactics=["Discovery"],
        description="Adversaries may attempt to identify the primary user, currently logged-in user, or set of users.",
        reference_url="https://attack.mitre.org/techniques/T1033/",
        is_subtechnique=False,
    ),

    # Initial Access & Valid Accounts
    "T1078": CatalogTechniqueEntry(
        technique_id="T1078",
        name="Valid Accounts",
        tactics=["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access.",
        reference_url="https://attack.mitre.org/techniques/T1078/",
        is_subtechnique=False,
    ),
    "T1078.003": CatalogTechniqueEntry(
        technique_id="T1078.003",
        name="Valid Accounts: Local Accounts",
        tactics=["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        description="Adversaries may obtain and abuse credentials of a local account to gain access or elevate privileges.",
        reference_url="https://attack.mitre.org/techniques/T1078/003/",
        is_subtechnique=True,
        parent_technique_id="T1078",
    ),

    # Command and Control
    "T1071": CatalogTechniqueEntry(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactics=["Command and Control"],
        description="Adversaries may communicate using application layer protocols to avoid detection/network filtering.",
        reference_url="https://attack.mitre.org/techniques/T1071/",
        is_subtechnique=False,
    ),
    "T1071.001": CatalogTechniqueEntry(
        technique_id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactics=["Command and Control"],
        description="Adversaries may communicate using application layer web protocols (HTTP/HTTPS) to blend in with normal traffic.",
        reference_url="https://attack.mitre.org/techniques/T1071/001/",
        is_subtechnique=True,
        parent_technique_id="T1071",
    ),
    "T1105": CatalogTechniqueEntry(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactics=["Command and Control"],
        description="Adversaries may transfer tools or other files from an external system into a compromised environment.",
        reference_url="https://attack.mitre.org/techniques/T1105/",
        is_subtechnique=False,
    ),

    # Lateral Movement
    "T1021": CatalogTechniqueEntry(
        technique_id="T1021",
        name="Remote Services",
        tactics=["Lateral Movement"],
        description="Adversaries may use valid accounts to log into a service that is designed to be remotely accessible.",
        reference_url="https://attack.mitre.org/techniques/T1021/",
        is_subtechnique=False,
    ),
    "T1021.004": CatalogTechniqueEntry(
        technique_id="T1021.004",
        name="Remote Services: SSH",
        tactics=["Lateral Movement"],
        description="Adversaries may use SSH to log into remote systems using valid credentials or keys.",
        reference_url="https://attack.mitre.org/techniques/T1021/004/",
        is_subtechnique=True,
        parent_technique_id="T1021",
    ),
    "T1570": CatalogTechniqueEntry(
        technique_id="T1570",
        name="Lateral Tool Transfer",
        tactics=["Lateral Movement"],
        description="Adversaries may transfer tools or other files between systems in a compromised environment.",
        reference_url="https://attack.mitre.org/techniques/T1570/",
        is_subtechnique=False,
    ),

    # Impact
    "T1485": CatalogTechniqueEntry(
        technique_id="T1485",
        name="Data Destruction",
        tactics=["Impact"],
        description="Adversaries may destroy data and files on specific systems or in large numbers to disrupt availability.",
        reference_url="https://attack.mitre.org/techniques/T1485/",
        is_subtechnique=False,
    ),
    "T1486": CatalogTechniqueEntry(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactics=["Impact"],
        description="Adversaries may encrypt data on target systems to interrupt availability to system and network resources.",
        reference_url="https://attack.mitre.org/techniques/T1486/",
        is_subtechnique=False,
    ),
    "T1489": CatalogTechniqueEntry(
        technique_id="T1489",
        name="Service Stop",
        tactics=["Impact"],
        description="Adversaries may stop or disable services on a system to render them unavailable to legitimate users.",
        reference_url="https://attack.mitre.org/techniques/T1489/",
        is_subtechnique=False,
    ),
}


def get_catalog_version() -> str:
    """Return the authoritative catalog version."""
    return MITRE_CATALOG_VERSION


def is_known_technique(technique_id: str) -> bool:
    """Check if the technique ID exists in the local catalog."""
    clean_id = technique_id.strip().upper()
    return clean_id in MITRE_CATALOG


def get_technique_info(technique_id: str) -> Optional[CatalogTechniqueEntry]:
    """Retrieve technique details from the local catalog."""
    clean_id = technique_id.strip().upper()
    return MITRE_CATALOG.get(clean_id)


def lookup_technique_or_fallback(technique_id: str) -> CatalogTechniqueEntry:
    """Lookup technique with deterministic fallback for uncataloged IDs.

    Guarantees no runtime failures or external dependencies.
    """
    clean_id = technique_id.strip().upper()
    entry = MITRE_CATALOG.get(clean_id)
    if entry:
        return entry

    # Fallback entry for uncataloged valid format IDs
    return CatalogTechniqueEntry(
        technique_id=clean_id,
        name=f"Custom Technique ({clean_id})",
        tactics=["Uncategorized"],
        description=f"Technique {clean_id} detected in rule or threat intelligence metadata.",
        reference_url=f"https://attack.mitre.org/techniques/{clean_id.replace('.', '/')}/",
        is_subtechnique="." in clean_id,
    )
