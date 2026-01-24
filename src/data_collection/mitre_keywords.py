"""
MITRE ATT&CK Framework Keywords
Critical techniques extracted from MITRE ATT&CK Enterprise v14
"""

# Critical severity keywords (Initial Access, Privilege Escalation, Lateral Movement)
MITRE_CRITICAL_KEYWORDS = [
    # Ransomware & Destructive
    'ransomware',
    'wiper',
    'data destruction',
    'disk encryption',
    
    # Supply Chain
    'supply chain attack',
    'supply chain compromise',
    'software supply chain',
    'trusted relationship',
    
    # Zero-Day & Exploits
    'zero-day',
    'zero day',
    'n-day exploit',
    'remote code execution',
    'rce',
    'code injection',
    'command injection',
    
    # Privilege Escalation
    'privilege escalation',
    'token manipulation',
    'access token manipulation',
    'sudo abuse',
    'setuid',
    'dll hijacking',
    
    # Lateral Movement
    'lateral movement',
    'pass the hash',
    'pass the ticket',
    'remote service',
    'psexec',
    'wmi execution',
    
    # Credential Access
    'credential dumping',
    'credentials from password stores',
    'lsass',
    'mimikatz',
    'brute force',
    'password spraying',
    
    # Persistence
    'backdoor',
    'implant',
    'bootkit',
    'rootkit',
    'scheduled task',
    'registry run key',
    
    # Initial Access
    'phishing',
    'spearphishing',
    'watering hole',
    'drive-by compromise',
    'exploit public-facing application',
    
    # Command & Control
    'command and control',
    'c2',
    'c&c',
    'beaconing',
    'dns tunneling',
    
    # Exfiltration
    'data exfiltration',
    'exfiltration over c2',
    'automated exfiltration',
    'transfer data to cloud',
    
    # Defense Evasion
    'obfuscation',
    'process injection',
    'reflective dll injection',
    'process hollowing',
    'defense evasion',
    'disable security tools',
    'indicator removal',
]

# High severity keywords
MITRE_HIGH_KEYWORDS = [
    'execution',
    'persistence',
    'defense evasion',
    'powershell',
    'cmd',
    'macro',
    'scripting',
    'windows management instrumentation',
]

# Medium severity keywords
MITRE_MEDIUM_KEYWORDS = [
    'discovery',
    'collection',
    'reconnaissance',
    'network scanning',
    'port scanning',
    'credential scanning',
]

# Threat actor groups (APT naming)
APT_GROUPS = [
    'apt1', 'apt28', 'apt29', 'apt32', 'apt33', 'apt34', 'apt37', 'apt38', 'apt39', 'apt41',
    'lazarus', 'fancy bear', 'cozy bear', 'carbanak', 'fin7', 'fin8',
    'sandworm', 'turla', 'equation group', 'winnti', 'dragonfly',
]

# Common malware families
MALWARE_FAMILIES = [
    'emotet', 'trickbot', 'ryuk', 'maze', 'revil', 'sodinokibi',
    'cobalt strike', 'metasploit', 'conti', 'lockbit', 'blackcat',
    'wannacry', 'notpetya', 'petya', 'bad rabbit',
]

def get_all_keywords():
    """Get combined list of all keywords"""
    return (MITRE_CRITICAL_KEYWORDS + 
            MITRE_HIGH_KEYWORDS + 
            MITRE_MEDIUM_KEYWORDS + 
            APT_GROUPS + 
            MALWARE_FAMILIES)

def get_keyword_severity(keyword: str) -> str:
    """Get severity level for a keyword"""
    keyword_lower = keyword.lower()
    
    if keyword_lower in MITRE_CRITICAL_KEYWORDS:
        return 'critical'
    elif keyword_lower in MITRE_HIGH_KEYWORDS:
        return 'high'
    elif keyword_lower in MITRE_MEDIUM_KEYWORDS:
        return 'medium'
    elif keyword_lower in APT_GROUPS or keyword_lower in MALWARE_FAMILIES:
        return 'high'
    else:
        return 'low'

if __name__ == "__main__":
    # Test keyword loading
    print(f"Total MITRE keywords loaded: {len(get_all_keywords())}")
    print(f"Critical keywords: {len(MITRE_CRITICAL_KEYWORDS)}")
    print(f"High keywords: {len(MITRE_HIGH_KEYWORDS)}")
    print(f"Medium keywords: {len(MITRE_MEDIUM_KEYWORDS)}")
    print(f"APT groups: {len(APT_GROUPS)}")
    print(f"Malware families: {len(MALWARE_FAMILIES)}")