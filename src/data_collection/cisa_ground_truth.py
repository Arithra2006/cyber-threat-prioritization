"""
CISA Ground Truth - Verified Critical Incidents
Manually curated high-impact cybersecurity incidents from CISA advisories
Used for evaluation and similarity scoring
"""

CISA_CRITICAL_INCIDENTS = [
    {
        'id': 'CISA-2020-SOLARWINDS',
        'name': 'SolarWinds Supply Chain Attack',
        'date': '2020-12-13',
        'description': (
            'Advanced persistent threat actors compromised SolarWinds Orion software updates, '
            'inserting a backdoor trojan (SUNBURST) that affected thousands of organizations globally. '
            'The supply chain compromise enabled persistent access to victim networks through '
            'legitimate software update mechanisms, demonstrating sophisticated tactics for '
            'initial access and persistence in enterprise environments.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'persistence', 'command-and-control'],
    },
    {
        'id': 'CISA-2021-COLONIAL',
        'name': 'Colonial Pipeline Ransomware Attack',
        'date': '2021-05-07',
        'description': (
            'DarkSide ransomware gang targeted Colonial Pipeline, the largest fuel pipeline in the US, '
            'forcing a complete shutdown of operations. The attack used stolen credentials for initial access '
            'and deployed ransomware that encrypted critical operational systems. The incident highlighted '
            'vulnerabilities in critical infrastructure and the impact of ransomware on physical operations.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'lateral-movement', 'impact'],
    },
    {
        'id': 'CISA-2021-LOG4J',
        'name': 'Log4j Remote Code Execution Vulnerability',
        'date': '2021-12-10',
        'description': (
            'Critical zero-day vulnerability (CVE-2021-44228) in Apache Log4j logging library allowed '
            'unauthenticated remote code execution via specially crafted JNDI lookup strings. '
            'The widespread use of Log4j in Java applications created massive attack surface affecting '
            'millions of systems globally. Threat actors actively exploited this for initial access, '
            'deploying cryptocurrency miners, ransomware, and remote access trojans.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'execution'],
    },
    {
        'id': 'CISA-2021-EXCHANGE',
        'name': 'Microsoft Exchange ProxyLogon Vulnerabilities',
        'date': '2021-03-02',
        'description': (
            'Multiple zero-day vulnerabilities in Microsoft Exchange Server allowed attackers to '
            'bypass authentication and execute arbitrary code on vulnerable servers. Chinese APT group '
            'HAFNIUM exploited these vulnerabilities for initial access, deploying web shells for persistence '
            'and exfiltrating sensitive data from email systems. Over 30,000 US organizations were compromised.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'persistence', 'credential-access'],
    },
    {
        'id': 'CISA-2021-KASEYA',
        'name': 'Kaseya VSA Ransomware Supply Chain Attack',
        'date': '2021-07-02',
        'description': (
            'REvil ransomware gang exploited zero-day vulnerability in Kaseya VSA remote management software, '
            'compromising managed service providers (MSPs) to deploy ransomware to downstream customers. '
            'The supply chain attack affected approximately 1,500 organizations through trusted MSP relationships, '
            'demonstrating the multiplier effect of targeting software supply chains.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'execution', 'impact'],
    },
    {
        'id': 'CISA-2022-LAPSUS',
        'name': 'LAPSUS$ Extortion Campaign',
        'date': '2022-03-22',
        'description': (
            'LAPSUS$ threat group conducted social engineering and SIM swapping attacks to compromise '
            'employee credentials at major technology companies including Microsoft, Okta, and NVIDIA. '
            'The group focused on stealing source code and proprietary data for extortion, using purchased '
            'credentials from underground markets and exploiting weak multi-factor authentication implementations.'
        ),
        'severity': 'high',
        'mitre_tactics': ['initial-access', 'credential-access', 'exfiltration'],
    },
    {
        'id': 'CISA-2023-MOVEit',
        'name': 'MOVEit Transfer SQL Injection Zero-Day',
        'date': '2023-05-31',
        'description': (
            'Critical SQL injection vulnerability (CVE-2023-34362) in Progress MOVEit Transfer file transfer software '
            'exploited by Cl0p ransomware gang. Attackers used the zero-day to steal data from organizations '
            'before deploying ransomware, affecting hundreds of organizations including government agencies, '
            'universities, and healthcare providers through managed file transfer compromise.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'exfiltration'],
    },
    {
        'id': 'CISA-2023-3CX',
        'name': '3CX Supply Chain Compromise',
        'date': '2023-03-29',
        'description': (
            'North Korean threat actors compromised 3CX desktop application through supply chain attack, '
            'distributing trojanized installers to 600,000+ users globally. The malicious update included '
            'backdoor functionality for command-and-control communications, enabling persistent access '
            'for espionage and credential theft across thousands of organizations.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'persistence', 'command-and-control'],
    },
    {
        'id': 'CISA-2022-CONFLUENCE',
        'name': 'Atlassian Confluence Remote Code Execution',
        'date': '2022-06-02',
        'description': (
            'Critical unauthenticated remote code execution vulnerability (CVE-2022-26134) in Atlassian Confluence '
            'Server and Data Center allowed attackers to execute arbitrary code through OGNL injection. '
            'Widely exploited for deploying web shells, cryptocurrency miners, and establishing persistent '
            'access to corporate knowledge bases containing sensitive intellectual property.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'execution', 'persistence'],
    },
    {
        'id': 'CISA-2023-BARRACUDA',
        'name': 'Barracuda Email Security Gateway Zero-Day',
        'date': '2023-05-23',
        'description': (
            'Chinese espionage group UNC4841 exploited zero-day vulnerability in Barracuda Email Security Gateway '
            'appliances for remote command injection. Attackers deployed sophisticated malware for persistent access, '
            'targeting government, military, and defense organizations for long-term espionage operations '
            'through compromised email security infrastructure.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'persistence', 'collection'],
    },
    {
        'id': 'CISA-2024-IVANTI',
        'name': 'Ivanti Connect Secure VPN Zero-Days',
        'date': '2024-01-10',
        'description': (
            'Multiple zero-day vulnerabilities in Ivanti Connect Secure VPN appliances allowed '
            'authentication bypass and remote code execution. Chinese state-sponsored groups exploited these '
            'vulnerabilities to compromise VPN gateways, deploying custom malware for credential harvesting '
            'and lateral movement into corporate networks through trusted remote access infrastructure.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'credential-access', 'lateral-movement'],
    },
    {
        'id': 'CISA-2022-FORTINET',
        'name': 'FortiOS SSL-VPN Authentication Bypass',
        'date': '2022-10-10',
        'description': (
            'Authentication bypass vulnerability (CVE-2022-40684) in FortiOS and FortiProxy SSL-VPN allowed '
            'unauthenticated attackers to perform administrative operations via crafted HTTP requests. '
            'Widely exploited for initial access to corporate networks, allowing attackers to modify firewall '
            'configurations, create rogue admin accounts, and establish persistent backdoors.'
        ),
        'severity': 'critical',
        'mitre_tactics': ['initial-access', 'persistence', 'defense-evasion'],
    },
]

def get_ground_truth_incidents():
    """Return list of CISA critical incidents for evaluation"""
    return CISA_CRITICAL_INCIDENTS

def get_incident_descriptions():
    """Return list of incident descriptions for embedding"""
    return [incident['description'] for incident in CISA_CRITICAL_INCIDENTS]

def get_incident_by_id(incident_id: str):
    """Get specific incident by ID"""
    for incident in CISA_CRITICAL_INCIDENTS:
        if incident['id'] == incident_id:
            return incident
    return None

if __name__ == "__main__":
    # Test ground truth loading
    incidents = get_ground_truth_incidents()
    print(f"✅ Loaded {len(incidents)} CISA critical incidents")
    print(f"\nIncident names:")
    for inc in incidents:
        print(f"  - {inc['name']} ({inc['date']})")
    
    print(f"\nAverage description length: {sum(len(inc['description']) for inc in incidents) / len(incidents):.0f} chars")