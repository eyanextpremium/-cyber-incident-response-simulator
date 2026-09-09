# Scenarios Documentation

## Overview

The Cyber Incident Response Simulator includes a comprehensive library of training scenarios that simulate real-world cyber attacks. These scenarios are designed to train security analysts in incident response procedures across various difficulty levels and attack types.

## Scenario Structure

### Scenario Format

Scenarios are defined in JSON format with the following structure:

```json
{
  "id": "scenario_id",
  "name": "Scenario Name",
  "difficulty": "beginner|intermediate|advanced|expert",
  "category": "attack_category",
  "description": "Detailed description of the scenario",
  "objective": "Learning objective for the analyst",
  "time_limit_secs": 600,
  "events": [
    {
      "offset_secs": 0,
      "source": "authentication",
      "event_type": "login_attempt",
      "message": "Event message",
      "host": "hostname",
      "source_ip": "ip_address",
      "user_name": "username",
      "mitre_technique": "T1110",
      "is_malicious": true
    }
  ],
  "expected_actions": [
    "Detect the brute force attack",
    "Identify the source IP",
    "Block the malicious IP",
    "Reset compromised credentials"
  ],
  "hints": [
    "Look for multiple failed login attempts",
    "Check authentication logs for patterns"
  ]
}
```

### Scenario Components

**Metadata:**
- `id`: Unique identifier for the scenario
- `name`: Display name
- `difficulty`: Difficulty level (beginner, intermediate, advanced, expert)
- `category`: Attack category (authentication, malware, network, etc.)
- `description`: Detailed description
- `objective`: Learning objective
- `time_limit_secs`: Time limit for completion

**Events:**
- `offset_secs`: Time offset from scenario start
- `source`: Log source (authentication, firewall, endpoint, etc.)
- `event_type`: Type of security event
- `message`: Event message
- `host`: Affected host
- `source_ip`: Source IP address
- `destination_ip`: Destination IP address
- `user_name`: User involved
- `mitre_technique`: MITRE ATT&CK technique ID
- `is_malicious`: Whether the event is malicious

**Expected Actions:**
- List of actions the analyst should take
- Used for scoring and evaluation

**Hints:**
- Optional hints for analysts
- Can be revealed during the scenario

## Difficulty Levels

### Beginner Scenarios

**Target Audience:** New security analysts and SOC operators
**Focus:** Basic detection and response procedures
**Time Limit:** 10-15 minutes
**Complexity:** Low

**Characteristics:**
- Single-vector attacks
- Clear indicators
- Minimal correlation required
- Straightforward response procedures

### Intermediate Scenarios

**Target Audience:** Experienced SOC analysts
**Focus:** Multi-vector attacks and correlation
**Time Limit:** 15-20 minutes
**Complexity:** Medium

**Characteristics:**
- Multiple attack vectors
- Event correlation required
- Some false positives
- Complex response procedures

### Advanced Scenarios

**Target Audience:** Senior analysts and incident responders
**Focus:** Sophisticated attacks and advanced techniques
**Time Limit:** 20-30 minutes
**Complexity:** High

**Characteristics:**
- Advanced attack techniques
- High false positive rate
- Multiple stages
- Complex decision-making

### Expert Scenarios

**Target Audience:** Expert incident responders and threat hunters
**Focus:** APT-level attacks and advanced persistent threats
**Time Limit:** 30-45 minutes
**Complexity:** Very High

**Characteristics:**
- APT simulation
- Living-off-the-land techniques
- Multiple attack chains
- Strategic decision-making

## Scenario Categories

### Authentication Attacks

**Description:** Attacks targeting authentication systems

**Techniques:**
- Brute force attacks
- Credential stuffing
- Password spraying
- Authentication bypass

**MITRE Tactics:**
- Initial Access (T1190, T1566)
- Credential Access (T1110, T1552)

### Malware Attacks

**Description:** Malware infections and malicious software

**Techniques:**
- Virus infection
- Ransomware
- Spyware
- Trojan horses

**MITRE Tactics:**
- Initial Access (T1190, T1566)
- Execution (T1204, T1059)
- Persistence (T1547, T1053)

### Network Attacks

**Description:** Network-based attacks and intrusions

**Techniques:**
- Port scanning
- Network sniffing
- Man-in-the-middle
- DDoS attacks

**MITRE Tactics:**
- Discovery (T1018, T1087)
- Lateral Movement (T1021, T1077)
- Collection (T1113, T1005)

### Web Application Attacks

**Description:** Attacks against web applications

**Techniques:**
- SQL injection
- XSS attacks
- CSRF attacks
- File inclusion

**MITRE Tactics:**
- Initial Access (T1190)
- Execution (T1204)
- Exfiltration (T1567)

### Data Exfiltration

**Description:** Unauthorized data transfer

**Techniques:**
- Data theft
- Insider threats
- Cloud exfiltration
- Physical data removal

**MITRE Tactics:**
- Collection (T1005, T1113)
- Exfiltration (T1041, T1567)

### Advanced Persistent Threats

**Description:** Sophisticated, long-term attacks

**Techniques:**
- APT simulation
- Custom malware
- Supply chain attacks
- Living-off-the-land

**MITRE Tactics:**
- Multiple tactics across the attack chain

## Available Scenarios

### Beginner Scenarios

#### 1. Brute Force Attack

**ID:** `brute_force`
**Category:** Authentication
**Time Limit:** 600 seconds

**Description:**
An attacker is attempting to brute force the administrator account on the domain controller. Multiple failed login attempts are detected from a single IP address.

**Objective:**
Detect and respond to a brute force authentication attack.

**MITRE Techniques:**
- T1110: Brute Force

**Expected Actions:**
- Detect the brute force attack pattern
- Identify the source IP address
- Block the malicious IP
- Reset the administrator password
- Document the incident

**Hints:**
- Look for multiple failed login attempts from the same IP
- Check authentication logs for patterns
- Consider implementing account lockout policies

#### 2. Malware Infection

**ID:** `malware`
**Category:** Malware
**Time Limit:** 600 seconds

**Description:**
A workstation has been infected with malware through a malicious email attachment. The malware is attempting to establish C2 communication and spread to other systems.

**Objective:**
Detect and contain a malware infection.

**MITRE Techniques:**
- T1566: Phishing
- T1204: User Execution
- T1071: Application Layer Protocol

**Expected Actions:**
- Identify the infected host
- Isolate the affected system
- Identify the malware variant
- Block C2 communication
- Scan other systems for infection

**Hints:**
- Look for suspicious process executions
- Check for unusual network connections
- Analyze the email that delivered the malware

#### 3. Phishing Campaign

**ID:** `phishing`
**Category:** Authentication
**Time Limit:** 600 seconds

**Description:**
A phishing campaign is targeting employees with fake login pages. Several users have clicked on malicious links and entered their credentials.

**Objective:**
Detect and respond to a phishing campaign.

**MITRE Techniques:**
- T1566: Phishing
- T1598: Phishing for Information

**Expected Actions:**
- Identify the phishing emails
- Identify affected users
- Block the phishing domain
- Reset compromised credentials
- Educate affected users

**Hints:**
- Look for emails with suspicious links
- Check for successful logins from unusual locations
- Analyze email headers for signs of spoofing

### Intermediate Scenarios

#### 1. Credential Theft

**ID:** `credential_theft`
**Category:** Authentication
**Time Limit:** 900 seconds

**Description:**
An attacker has stolen user credentials through a keylogger and is using them to access sensitive systems. The attack involves lateral movement and privilege escalation.

**Objective:**
Detect and respond to credential theft and lateral movement.

**MITRE Techniques:**
- T1056: Input Capture
- T1552: Unsecured Credentials
- T1021: Remote Services
- T1068: Privilege Escalation

**Expected Actions:**
- Identify compromised credentials
- Determine scope of compromise
- Reset all affected credentials
- Identify lateral movement paths
- Implement enhanced monitoring

**Hints:**
- Look for logins from unusual locations
- Check for privilege escalation events
- Analyze authentication patterns

#### 2. Lateral Movement

**ID:** `lateral_movement`
**Category:** Network
**Time Limit:** 900 seconds

**Description:**
An attacker has gained initial access and is moving laterally through the network using valid credentials. Multiple systems show signs of unauthorized access.

**Objective:**
Detect and contain lateral movement.

**MITRE Techniques:**
- T1021: Remote Services
- T1077: Windows Admin Shares
- T1558: Kerberoasting

**Expected Actions:**
- Identify the attack entry point
- Map lateral movement paths
- Isolate affected systems
- Reset compromised credentials
- Implement network segmentation

**Hints:**
- Look for authentication across multiple systems
- Check for unusual remote access
- Analyze network traffic patterns

#### 3. Privilege Escalation

**ID:** `privilege_escalation`
**Category:** Malware
**Time Limit:** 900 seconds

**Description:**
An attacker with limited access is attempting to escalate privileges to gain administrative control. Various privilege escalation techniques are being used.

**Objective:**
Detect and respond to privilege escalation attempts.

**MITRE Techniques:**
- T1068: Privilege Escalation
- T1548: Abuse Elevation Control Mechanism
- T1134: Access Token Manipulation

**Expected Actions:**
- Identify privilege escalation attempts
- Determine the attacker's current access level
- Limit further escalation
- Investigate the source of initial access
- Implement least privilege policies

**Hints:**
- Look for unusual process execution with admin rights
- Check for changes to user permissions
- Analyze UAC bypass attempts

### Advanced Scenarios

#### 1. Data Exfiltration

**ID:** `data_exfiltration`
**Category:** Data Exfiltration
**Time Limit:** 1200 seconds

**Description:**
An attacker has gained access to sensitive data and is exfiltrating it using various methods. The exfiltration is designed to bypass detection mechanisms.

**Objective:**
Detect and stop data exfiltration.

**MITRE Techniques:**
- T1005: Data from Local System
- T1041: Exfiltration Over C2 Channel
- T1567: Exfiltration Over Web Service

**Expected Actions:**
- Identify what data is being exfiltrated
- Determine exfiltration method
- Block data transfer
- Assess data exposure impact
- Implement DLP controls

**Hints:**
- Look for large data transfers
- Check for unusual outbound connections
- Analyze traffic patterns
- Monitor for encryption use

#### 2. Ransomware Attack

**ID:** `ransoware`
**Category:** Malware
**Time Limit:** 1200 seconds

**Description:**
A ransomware attack has encrypted critical files on multiple systems. The attacker is demanding payment for decryption. The attack has spread through the network.

**Objective:**
Respond to a ransomware attack and minimize impact.

**MITRE Techniques:**
- T1486: Data Encrypted for Impact
- T1059: Command and Scripting Interpreter
- T1021: Remote Services

**Expected Actions:**
- Identify all affected systems
- Isolate infected systems
- Identify ransomware variant
- Assess data loss
- Restore from backups
- Implement security improvements

**Hints:**
- Look for file encryption events
- Check for ransom notes
- Identify patient zero
- Assess backup availability

#### 3. Web Attack

**ID:** `web_attack`
**Category:** Web Application
**Time Limit:** 1200 seconds

**Description:**
The web server is under attack using various web application vulnerabilities. The attacker is attempting to inject malicious code and extract sensitive data.

**Objective:**
Detect and respond to web application attacks.

**MITRE Techniques:**
- T1190: Exploit Public-Facing Application
- T1195: Supply Chain Compromise
- T1055: Process Injection

**Expected Actions:**
- Identify the attack vector
- Patch vulnerabilities
- Block malicious requests
- Assess data compromise
- Implement web application firewall

**Hints:**
- Analyze web server logs
- Look for SQL injection patterns
- Check for XSS attempts
- Monitor for unusual requests

### Expert Scenarios

#### 1. APT Simulation

**ID:** `apt_simulation`
**Category:** Advanced Persistent Threat
**Time Limit:** 1800 seconds

**Description:**
An advanced persistent threat group has compromised the network using sophisticated techniques. The attack involves custom malware, living-off-the-land techniques, and long-term persistence.

**Objective:**
Detect and respond to an APT attack.

**MITRE Techniques:**
- Multiple techniques across the attack chain
- Custom malware and tools
- Living-off-the-land techniques
- Advanced evasion methods

**Expected Actions:**
- Identify APT presence
- Map attack chain
- Determine scope of compromise
- Remove persistence mechanisms
- Implement advanced monitoring

**Hints:**
- Look for subtle indicators
- Analyze long-term patterns
- Check for living-off-the-land techniques
- Use threat intelligence

#### 2. Custom Campaign

**ID:** `custom_campaign`
**Category:** Advanced Persistent Threat
**Time Limit:** 1800 seconds

**Description:**
A targeted attack campaign is using custom malware and techniques specifically designed for this environment. The attack shows signs of extensive reconnaissance and planning.

**Objective:**
Respond to a custom targeted attack.

**MITRE Techniques:**
- Custom malware and tools
- Targeted techniques
- Environmental adaptation
- Advanced evasion

**Expected Actions:**
- Identify custom malware
- Analyze attack techniques
- Determine attacker objectives
- Implement custom detection rules
- Enhance security posture

**Hints:**
- Look for unique patterns
- Analyze custom malware
- Understand attacker objectives
- Use behavioral analysis

#### 3. Multi-Stage Attack

**ID:** `multi_stage_attack`
**Category:** Advanced Persistent Threat
**Time Limit:** 1800 seconds

**Description:**
A complex multi-stage attack involves multiple attack vectors and techniques. The attacker adapts their approach based on defensive measures and uses fallback mechanisms.

**Objective:**
Detect and respond to a complex multi-stage attack.

**MITRE Techniques:**
- Multiple attack vectors
- Adaptive techniques
- Fallback mechanisms
- Multi-pronged approach

**Expected Actions:**
- Identify all attack stages
- Map attack progression
- Adapt response to attacker actions
- Implement comprehensive defenses
- Learn from attack techniques

**Hints:**
- Look for multiple attack vectors
- Analyze attack progression
- Consider attacker adaptation
- Implement layered defenses

## Scenario Creation

### Creating Custom Scenarios

Users can create custom scenarios by following the scenario structure:

1. **Define Scenario Metadata:**
   - Set difficulty level
   - Choose category
   - Write description and objective

2. **Create Events:**
   - Define event sequence
   - Set appropriate timing
   - Map to MITRE techniques
   - Mark malicious events

3. **Define Expected Actions:**
   - List required response actions
   - Set evaluation criteria
   - Define success metrics

4. **Add Hints:**
   - Provide helpful hints
   - Make hints progressive
   - Balance difficulty

### Scenario Testing

Test scenarios before deployment:

1. **Validate JSON structure**
2. **Test event generation**
3. **Verify detection rules**
4. **Test scoring logic**
5. **Review time limits**

### Scenario Deployment

Deploy scenarios to the simulator:

1. Place JSON file in `scenarios/` directory
2. Organize by difficulty level
3. Update scenario loader if needed
4. Test in development environment
5. Deploy to production

## Scenario Evaluation

### Scoring Criteria

Scenarios are evaluated based on:

- **Detection Accuracy:** Correct identification of malicious events
- **Response Speed:** Time taken to respond
- **Action Completeness:** Completeness of required actions
- **Documentation Quality:** Thoroughness of documentation
- **Adaptability:** Ability to handle unexpected developments

### Performance Metrics

Track performance metrics:

- Detection rate
- False positive rate
- Response time
- Containment effectiveness
- Recovery time

### Improvement Recommendations

Provide improvement recommendations:

- Areas for improvement
- Additional training needs
- Procedure updates
- Tool recommendations

## Scenario Maintenance

### Regular Updates

Regularly update scenarios to:

- Reflect new threat landscape
- Incorporate new MITRE techniques
- Improve realism
- Fix any issues

### Quality Assurance

Maintain scenario quality through:

- Regular testing
- User feedback collection
- Performance analysis
- Continuous improvement

### Version Control

Use version control for scenarios:

- Track changes
- Maintain history
- Enable rollback
- Facilitate collaboration

## Future Enhancements

### Planned Features
- Dynamic scenario generation
- AI-powered scenario adaptation
- Real-world threat feed integration
- Multi-user collaborative scenarios
- Advanced analytics and reporting
- Custom scenario editor
- Scenario marketplace

### Technical Improvements
- Enhanced event generation
- More realistic attack simulation
- Better detection rule integration
- Improved scoring algorithms
- Advanced visualization
- Real-time feedback