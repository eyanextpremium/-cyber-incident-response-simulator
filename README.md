# 🛡️ Cyber Incident Simulator

> **A modular, security-focused Cyber Incident Response & SIEM Simulation Platform built with Rust.**

Cyber Incident Simulator is a **realistic cybersecurity training and incident-response simulation platform** designed to reproduce security incidents, generate and process security events, detect malicious activity, investigate incidents, perform response actions, and evaluate analyst performance.

The platform combines **SIEM-style detection**, **MITRE ATT&CK-based attack scenarios**, **incident response workflows**, **digital evidence management**, **real-time monitoring**, and **performance scoring** into a single modular environment.

It is designed to provide a controlled environment where security analysts, students, developers, and cybersecurity enthusiasts can practice the complete lifecycle of handling a cyber incident.

---

## 🚀 Overview

Modern cybersecurity requires more than simply detecting an attack.

A security analyst must be able to:

* Identify suspicious activity
* Correlate security events
* Determine the severity of an incident
* Investigate affected systems
* Collect and analyze evidence
* Contain the threat
* Perform eradication and recovery
* Document the incident
* Evaluate the response

Cyber Incident Simulator models this workflow as an interactive simulation.

```text
┌─────────────────────────────────────────────────────────────┐
│                    CYBER INCIDENT SIMULATOR                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Attack Scenario                                            │
│       │                                                     │
│       ▼                                                     │
│  Event / Log Generation                                     │
│       │                                                     │
│       ▼                                                     │
│  Detection & Correlation Engine                             │
│       │                                                     │
│       ▼                                                     │
│  Alert Generation                                           │
│       │                                                     │
│       ▼                                                     │
│  Incident Management                                        │
│       │                                                     │
│       ▼                                                     │
│  Investigation & Evidence                                   │
│       │                                                     │
│       ▼                                                     │
│  Response / Containment / Recovery                          │
│       │                                                     │
│       ▼                                                     │
│  Scoring & Performance Evaluation                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

# ✨ Key Features

## 🔴 Cyber Attack Simulation

The simulator provides multiple attack and incident scenarios representing realistic adversarial behavior.

Supported scenario categories include:

* Brute Force
* Password Spraying
* Phishing
* Malware
* Ransomware
* SQL Injection
* Data Exfiltration
* Web Attacks
* Credential Theft
* Lateral Movement
* Privilege Escalation
* PowerShell Activity
* Command & Control
* DNS Tunneling
* Insider Threat
* Web Shell Activity
* Multi-stage Attack Campaigns
* APT-style simulations

Scenarios can be organized according to difficulty and attack progression.

---

# 🧠 MITRE ATT&CK Integration

The simulator uses the **MITRE ATT&CK framework** to model adversarial behavior.

Attack scenarios are mapped to ATT&CK tactics and techniques, allowing simulated incidents to represent realistic attack chains.

### ATT&CK tactic coverage includes:

* Reconnaissance
* Resource Development
* Initial Access
* Execution
* Persistence
* Privilege Escalation
* Defense Evasion
* Credential Access
* Discovery
* Lateral Movement
* Collection
* Command and Control
* Exfiltration
* Impact

This allows incidents to be analyzed not only as isolated alerts, but as parts of a larger adversary campaign.

---

# 🔎 Detection Engine

The detection layer acts as the core of the simulated security monitoring environment.

It processes generated security events and applies detection rules to identify suspicious behavior.

### Detection capabilities

* Rule-based detection
* Event correlation
* IOC analysis
* Severity classification
* MITRE technique mapping
* Alert generation
* Rule enable/disable management
* Multi-event detection
* Suspicious activity identification

The detection pipeline is designed around the same conceptual workflow used by modern security monitoring systems:

```text
Security Event
      │
      ▼
Event Parser
      │
      ▼
Detection Rules
      │
      ▼
Correlation Engine
      │
      ▼
IOC Analysis
      │
      ▼
Severity Classification
      │
      ▼
Security Alert
```

---

# 🚨 Incident Response

Detected threats can be transformed into structured incidents and managed through an incident-response lifecycle.

The system models the major phases of incident handling:

```text
Detection
   ↓
Investigation
   ↓
Containment
   ↓
Eradication
   ↓
Recovery
   ↓
Resolution
```

Response actions can be tracked and associated with the affected incident.

This makes the simulator useful not only for detection practice, but also for **full incident-response training**.

---

# 🔬 Investigation & Digital Evidence

The investigation subsystem provides a structured environment for analyzing incidents.

Capabilities include:

* Evidence collection
* Evidence tracking
* Incident timelines
* Event investigation
* Investigation queries
* Evidence metadata
* Timeline reconstruction
* Incident history

The goal is to simulate the process of answering questions such as:

> What happened?

> When did it happen?

> Which system was affected?

> How did the attacker gain access?

> What actions were performed?

> What evidence supports the conclusion?

---

# 📊 Analyst Scoring System

Cyber Incident Simulator evaluates the analyst's incident-response performance using a structured scoring model.

The scoring system considers four major response areas:

| Category      | Weight |
| ------------- | -----: |
| Detection     |    25% |
| Investigation |    25% |
| Containment   |    25% |
| Recovery      |    25% |

Additional factors such as response time can influence the final score.

This creates a training environment where analysts are not simply asked to **find an alert**, but are evaluated on their ability to manage the entire incident lifecycle.

---

# 👥 Role-Based Access Control

The platform includes role-based access control.

### Admin

Full system access including management and administrative operations.

### Analyst

Designed for security analysts investigating and responding to incidents.

### Trainee

Designed for cybersecurity training and simulation exercises.

The role system allows different users to interact with the platform according to their responsibilities.

---

# 🔐 Security Architecture

Security is treated as a core component of the platform rather than an additional feature.

Implemented security mechanisms include:

* Argon2id password hashing
* TOTP-based multi-factor authentication
* HMAC-SHA1 for TOTP verification
* SHA-256 hashing
* IP lockdown
* Brute-force protection
* Path traversal protection
* XSS protection
* Content Security Policy
* `X-Content-Type-Options`
* `X-Frame-Options`
* HSTS
* CORS controls
* Input validation
* Session management
* Role-based authorization

The application also follows a defense-in-depth approach across the API, authentication, data access, and frontend layers.

---

# ⚡ Real-Time Monitoring

The platform supports real-time communication between the backend and frontend.

Real-time functionality is used for:

* Security events
* Alerts
* Incident updates
* Simulation state
* Dashboard information
* Live monitoring

Supported communication mechanisms include:

* WebSocket
* Server-Sent Events
* UDP Syslog

---

# 📡 Syslog Support

The simulator includes a UDP-based Syslog listener designed around standard Syslog message formats.

Supported concepts include:

* RFC 3164
* RFC 5424
* UDP log ingestion
* Log parsing
* Security event generation

Default Syslog port:

```text
5140/UDP
```

This allows external log generators and security tools to feed simulated security events into the platform.

---

# 🏗️ Architecture

The project follows a modular Rust architecture.

```text
src/
├── api/
│   ├── handlers
│   ├── middleware
│   ├── routes
│   └── websocket
│
├── attack/
│   ├── MITRE integration
│   ├── procedures
│   ├── tactics
│   └── techniques
│
├── audit/
│   ├── attack auditing
│   ├── scanner
│   └── reports
│
├── config/
│   ├── environment
│   ├── loader
│   └── settings
│
├── database/
│   ├── connection
│   ├── queries
│   └── repository
│
├── detection/
│   ├── correlation
│   ├── engine
│   ├── IOC
│   ├── rules
│   └── severity
│
├── incident/
│   ├── lifecycle
│   ├── incident manager
│   └── state
│
├── investigation/
│   ├── engine
│   ├── evidence
│   ├── queries
│   └── timeline
│
├── logging/
│   ├── formatter
│   ├── generator
│   ├── logger
│   ├── parser
│   └── Syslog
│
├── response/
│   ├── actions
│   ├── containment
│   ├── eradication
│   ├── recovery
│   └── response engine
│
├── scenarios/
│   ├── generator
│   ├── loader
│   └── scenario models
│
├── scoring/
│   ├── engine
│   ├── metrics
│   └── ranking
│
├── simulation/
│   ├── clock
│   ├── engine
│   ├── session
│   └── state
│
└── utils/
    ├── IDs
    ├── security
    ├── time
    └── validation
```

---

# 🗄️ Database

The application uses **SQLite** for persistence.

Core entities include:

* Users
* Sessions
* Events
* Alerts
* Incidents
* Evidence
* Response Actions
* Scores
* Assets
* Banned IP Addresses

Conceptually:

```text
Users
  │
  └── Sessions
        │
        ▼
      Events
        │
        ▼
      Alerts
        │
        ▼
    Incidents
      ├── Evidence
      ├── Timeline
      └── Response Actions
              │
              ▼
            Score
```

---

# 🦀 Technology Stack

## Backend

* **Rust 2021**
* **Axum 0.7**
* **Tokio**
* **SQLite**
* **rusqlite**
* **Argon2**
* **HMAC**
* **SHA-256**
* **TOTP / RFC 6238**
* **Tracing**

## Frontend

* HTML5
* CSS3
* Vanilla JavaScript
* ES6 Modules
* WebSocket
* Server-Sent Events

No frontend framework is required.

---

# 🐳 Containerization

The project includes Docker support for reproducible deployment.

Included:

* Multi-stage Docker build
* Non-root application user
* Docker Compose
* Persistent storage
* Health checks
* API/Web interface
* Syslog listener

Default exposed services:

```text
Web / API
8080/TCP

Syslog
5140/UDP
```

---

# 🔄 CI / Security Automation

The repository includes GitHub Actions workflows for automated project checks.

The CI/security workflow covers areas such as:

* Rust compilation
* Testing
* Clippy analysis
* Dependency auditing
* Security-oriented checks

This helps maintain a repeatable development and validation workflow.

---

# 📁 Project Structure

```text
Cyber Incident Simulator/
│
├── .github/
├── config/
├── data/
├── docs/
├── fronted/
├── migrations/
├── scenarios/
├── scripts/
├── src/
├── tests/
│
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
├── docker-compose.yml
├── LICENSE
└── README.md
```

---

# ⚙️ Getting Started

## Requirements

Recommended environment:

* Rust
* Cargo
* SQLite
* Docker / Docker Compose (optional)

---

## Clone

```bash
git clone https://github.com/YOUR_USERNAME/cyber-incident-simulator.git
cd cyber-incident-simulator
```

---

## Configure

Create your environment configuration from the provided example:

```bash
cp .env.example .env
```

Adjust the configuration according to your environment.

---

## Build

```bash
cargo build
```

---

## Run

```bash
cargo run
```

The application will start the backend and expose the configured web/API services.

---

# 🐳 Docker

Build and start the complete environment with:

```bash
docker compose up --build
```

Run in detached mode:

```bash
docker compose up -d --build
```

Stop the environment:

```bash
docker compose down
```

---

# 🧪 Testing

Run the complete Rust test suite:

```bash
cargo test
```

Run a specific integration test:

```bash
cargo test --test e2e_flow
```

Run tests with output:

```bash
cargo test -- --nocapture
```

---

# 🎯 Training Workflow

A typical training session can follow this workflow:

### 1. Select a Scenario

Choose an incident scenario based on difficulty or attack type.

### 2. Start Simulation

The simulator generates security activity representing the selected attack.

### 3. Monitor Events

Observe incoming events and suspicious activity through the monitoring interface.

### 4. Analyze Alerts

Review generated alerts and determine their severity.

### 5. Investigate

Analyze:

* Events
* Timeline
* Assets
* Evidence
* Attack techniques

### 6. Contain

Perform appropriate containment actions.

### 7. Recover

Complete recovery actions and return affected systems to a stable state.

### 8. Review Score

The system evaluates the analyst's overall incident-response performance.

---

# 🧩 Example Attack Chain

A multi-stage simulated attack can look like:

```text
Initial Access
      │
      ▼
Credential Access
      │
      ▼
Execution
      │
      ▼
Privilege Escalation
      │
      ▼
Lateral Movement
      │
      ▼
Collection
      │
      ▼
Command & Control
      │
      ▼
Exfiltration
      │
      ▼
Impact
```

The detection and investigation layers allow the analyst to reconstruct this progression from security events and alerts.

---

# 🛡️ Security Philosophy

The project is built around a simple principle:

> **Detection is only the beginning of incident response.**

A capable security platform should connect:

```text
Telemetry
   ↓
Detection
   ↓
Correlation
   ↓
Investigation
   ↓
Evidence
   ↓
Response
   ↓
Recovery
   ↓
Evaluation
```

Cyber Incident Simulator is designed around this complete lifecycle.

---

# 📚 Documentation

Additional technical documentation is available in the `docs/` directory.

Documentation includes:

* API documentation
* System architecture
* Database design
* Incident response workflow
* Scenario system
* Threat model

---

# 🎓 Who Is This For?

Cyber Incident Simulator can be useful for:

* Cybersecurity students
* SOC analyst trainees
* Security researchers
* Software engineers learning cybersecurity
* Blue team practitioners
* Incident responders
* Cybersecurity educators
* Developers interested in security engineering

---

# 💡 Why Rust?

Rust was selected for the backend because it provides:

* Memory safety
* Strong type safety
* High performance
* Predictable resource usage
* Excellent concurrency primitives
* Reliable error handling
* Strong ecosystem for network services

For a security-oriented simulation platform, these properties provide a strong foundation for building reliable backend components.

---

# 📌 Project Goals

The primary goals of Cyber Incident Simulator are:

* Build a realistic incident-response environment
* Model real-world attack behavior
* Integrate MITRE ATT&CK concepts
* Provide security event detection
* Enable structured incident investigation
* Simulate containment and recovery
* Evaluate analyst performance
* Provide a modular cybersecurity architecture
* Demonstrate secure Rust backend engineering

---

# 🏆 Project Highlights

| Area             | Capability                                         |
| ---------------- | -------------------------------------------------- |
| Backend          | Rust + Axum + Tokio                                |
| Database         | SQLite                                             |
| Detection        | Rules + Correlation + IOC                          |
| Attack Framework | MITRE ATT&CK                                       |
| Authentication   | Argon2id + TOTP                                    |
| Authorization    | RBAC                                               |
| Logging          | Structured logging + Syslog                        |
| Real-Time        | WebSocket + SSE                                    |
| Investigation    | Evidence + Timeline                                |
| Response         | Containment + Eradication + Recovery               |
| Scoring          | Detection + Investigation + Containment + Recovery |
| Deployment       | Docker + Docker Compose                            |
| Automation       | GitHub Actions                                     |
| Frontend         | HTML + CSS + Vanilla JS                            |

---

# 📜 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

---

# 👨‍💻 About the Project

Cyber Incident Simulator is a personal cybersecurity engineering project focused on combining:

**Software Engineering + Cybersecurity + Incident Response + Simulation + Security Architecture**

The project is built with the goal of creating a practical environment where cybersecurity concepts can be transformed into an interactive technical system rather than remaining purely theoretical.

---

<p align="center">

### 🛡️ Detect. Investigate. Contain. Recover.

**Cyber Incident Simulator**

Built with ❤️ and Rust.

</p>
