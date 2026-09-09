# Architecture Documentation

## System Overview

The Cyber Incident Response Simulator is a web-based SOC training platform built with Rust (Axum framework) for the backend and vanilla JavaScript for the frontend. It simulates cyber security incidents to train security analysts in incident response procedures.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Dashboard│ │Scenarios │ │Incidents │ │Investigate│      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│         │            │            │            │            │
│         └────────────┴────────────┴────────────┘            │
│                        │                                     │
│              HTTP/JSON API                                    │
└────────────────────────│────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                      Backend (Rust)                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    API Layer                           │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐│  │
│  │  │ Handlers │ │  Routes  │ │Middleware│ │  Errors  ││  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘│  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  Business Logic                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐│  │
│  │  │Detection │ │Incident  │ │Investigate│ │ Response ││  │
│  │  │  Engine  │ │ Manager  │ │  Engine   │ │  Engine  ││  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘│  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐│  │
│  │  │Simulation│ │ Scoring  │ │  Attack  │ │ Scenarios││  │
│  │  │  Engine  │ │  Engine  │ │  MITRE   │ │  Loader  ││  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘│  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  Data Layer                            │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐│  │
│  │  │Repository│ │  Queries │ │ Connection│ │  Models  ││  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘│  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────│────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                   Data Storage                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ SQLite   │ │Scenario  │ │  Config  │ │   Logs   │      │
│  │ Database │ │  Files   │ │  Files   │ │  Files   │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. API Layer

**Purpose:** Handle HTTP requests and responses, route to appropriate handlers.

**Components:**
- **Routes (`src/api/routes.rs`):** Define URL patterns and map to handlers
- **Handlers (`src/api/handlers.rs`):** Process requests, call business logic, return responses
- **Middleware (`src/api/middleware.rs`):** Request/response processing (CORS, logging, etc.)
- **Errors (`src/api/errors.rs`):** Custom error types and response formatting

**Key Features:**
- RESTful API design
- JSON request/response format
- Error handling with proper HTTP status codes
- CORS support for frontend integration

### 2. Detection Engine

**Purpose:** Analyze security events and generate alerts based on detection rules.

**Components:**
- **Detection Engine (`src/detection/engine.rs`):** Core detection logic
- **Rule System (`src/detection/rule.rs`):** Rule definition and evaluation
- **Correlation Engine (`src/detection/correlation.rs`):** Multi-event correlation
- **IOC Detection (`src/detection/ioc.rs`):** Indicator of Compromise detection

**Detection Flow:**
```
Event → Rule Evaluation → Correlation → Alert Generation → Database
```

**Rule Types:**
- Simple pattern matching
- Threshold-based detection
- Behavioral analysis
- IOC matching
- MITRE ATT&CK technique mapping

### 3. Incident Management

**Purpose:** Manage incident lifecycle from detection to resolution.

**Components:**
- **Incident Manager (`src/incident/manager.rs`):** Create, update, close incidents
- **Lifecycle (`src/incident/lifecycle.rs`):** State machine for incident progression
- **State (`src/incident/state.rs`):** Incident state tracking

**Incident Lifecycle:**
```
Detected → Investigating → Contained → Eradicated → Recovered → Closed
```

**Features:**
- Automatic incident creation from alerts
- Manual incident creation
- Status tracking and updates
- Alert-to-incident correlation
- Timeline management

### 4. Investigation Engine

**Purpose:** Provide tools for incident investigation and evidence collection.

**Components:**
- **Investigation Engine (`src/investigation/engine.rs`):** Core investigation logic
- **Evidence Collection (`src/investigation/evidence.rs`):** Evidence gathering
- **Timeline Builder (`src/investigation/timeline.rs`):** Attack timeline construction
- **Query Engine (`src/investigation/queries.rs`):** Event querying and filtering

**Investigation Features:**
- Event timeline visualization
- Evidence auto-collection
- Attack chain reconstruction
- MITRE ATT&CK technique mapping
- Cross-reference analysis

### 5. Response Engine

**Purpose:** Execute incident response actions and track remediation.

**Components:**
- **Response Engine (`src/response/engine.rs`):** Action execution logic
- **Actions (`src/response/actions.rs`):** Available response actions
- **Containment (`src/response/containment.rs`):** Containment procedures
- **Eradication (`src/response/eradication.rs`):** Threat removal procedures
- **Recovery (`src/response/recovery.rs`):** System recovery procedures

**Response Actions:**
- Host isolation
- IP blocking
- Process termination
- Account disabling
- Session revocation
- Vulnerability patching
- Backup restoration
- Artifact collection

### 6. Simulation Engine

**Purpose:** Generate realistic security events based on attack scenarios.

**Components:**
- **Simulation Engine (`src/simulation/engine.rs`):** Core simulation logic
- **Session Management (`src/simulation/session.rs`):** User session handling
- **State Management (`src/simulation/state.rs`):** Global simulation state
- **Clock (`src/simulation/clock.rs`):** Simulation time management

**Simulation Flow:**
```
Scenario Load → Event Generation → Detection → Alert → Database
```

**Features:**
- Time-based event emission
- Realistic log generation
- MITRE ATT&CK technique simulation
- Configurable event patterns
- Multi-stage attack simulation

### 7. Scoring Engine

**Purpose:** Evaluate analyst performance and calculate scores.

**Components:**
- **Scoring Engine (`src/scoring/engine.rs`):** Score calculation logic
- **Metrics (`src/scoring/metrics.rs`):** Performance metrics tracking
- **Ranking (`src/scoring/ranking.rs`):** Analyst ranking system

**Scoring Factors:**
- Detection speed and accuracy
- Investigation thoroughness
- Containment effectiveness
- Recovery speed
- Time efficiency
- False positive handling

**Score Calculation:**
```
Total Score = (Detection × 0.25) + (Investigation × 0.25) + 
              (Containment × 0.25) + (Recovery × 0.25) - Time Penalty
```

### 8. Scenario System

**Purpose:** Define and load attack scenarios for simulation.

**Components:**
- **Scenario Loader (`src/scenarios/loader.rs`):** Load scenario files
- **Scenario Generator (`src/scenarios/generator.rs`):** Generate events from scenarios
- **Scenario (`src/scenarios/scenario.rs`):** Scenario data structure
- **Difficulty (`src/scenarios/difficulty.rs`):** Difficulty levels

**Scenario Structure:**
```json
{
  "id": "scenario_id",
  "name": "Scenario Name",
  "difficulty": "beginner|intermediate|advanced|expert",
  "category": "attack_category",
  "description": "Description",
  "objective": "Learning objective",
  "time_limit_secs": 600,
  "events": [...],
  "expected_actions": [...],
  "hints": [...]
}
```

### 9. MITRE ATT&CK Integration

**Purpose:** Map attacks to MITRE ATT&CK framework for educational value.

**Components:**
- **MITRE (`src/attack/mitre.rs`):** MITRE ATT&CK data
- **Tactics (`src/attack/tactics.rs`):** Tactic definitions
- **Techniques (`src/attack/techniques.rs`):** Technique definitions
- **Procedures (`src/attack/procedures.rs`):** Procedure implementations

**Mapping:**
- Events → MITRE Techniques
- Alerts → MITRE Tactics
- Incidents → Attack Chains

### 10. Database Layer

**Purpose:** Persist all simulation data.

**Components:**
- **Connection (`src/database/connection.rs`):** Database connection management
- **Repository (`src/database/repository.rs`):** Data access patterns
- **Queries (`src/database/queries.rs`):** SQL query definitions
- **Models (`src/models/`):** Data models

**Database Schema:**
- Sessions
- Events
- Alerts
- Incidents
- Evidence
- Response Actions
- Scores
- Assets

**Technology:** SQLite with rusqlite crate

### 11. Logging System

**Purpose:** Generate realistic log files for simulation.

**Components:**
- **Logger (`src/logging/logger.rs`):** Log management
- **Generator (`src/logging/generator.rs`):** Log event generation
- **Parser (`src/logging/parser.rs`):** Log parsing
- **Formatter (`src/logging/formatter.rs`):** Log formatting

**Log Types:**
- Authentication logs
- Firewall logs
- Endpoint logs
- Web server logs
- Network logs

### 12. Configuration Management

**Purpose:** Load and manage application configuration.

**Components:**
- **Settings (`src/config/settings.rs`):** Configuration data structures
- **Loader (`src/config/loader.rs`):** Configuration file loading

**Configuration Files:**
- `config/simulator.toml` - Main configuration
- `config/detection_rules.toml` - Detection rules
- `config/scoring.toml` - Scoring configuration

## Data Flow

### Event Generation Flow
```
Scenario Definition → Event Generator → Event Database → Detection Engine → Alerts
```

### Incident Response Flow
```
Alerts → Incident Manager → Investigation Engine → Response Engine → Recovery
```

### Scoring Flow
```
Session Actions → Scoring Engine → Metrics Calculation → Ranking → Score Report
```

## Security Considerations

### Current State
- No authentication (intentional for simulator)
- No rate limiting
- SQLite database (file-based)
- Local deployment focus

### Production Recommendations
- Add authentication (OAuth, JWT)
- Implement rate limiting
- Use PostgreSQL/MySQL for production
- Add HTTPS/TLS
- Implement audit logging
- Add input validation
- Sanitize user inputs

## Performance Considerations

### Optimization Opportunities
- Implement caching for frequently accessed data
- Add database indexing
- Use connection pooling
- Implement WebSocket for real-time updates
- Add background job processing
- Optimize database queries

### Scalability
- Current design is single-server
- Can be scaled horizontally with load balancer
- Database can be migrated to cloud services
- Session storage can be moved to Redis

## Deployment Architecture

### Development
```
Local machine → Rust binary → SQLite → Frontend files
```

### Production (Recommended)
```
Load Balancer → Multiple Rust instances → PostgreSQL/Redis → CDN for static files
```

### Docker Deployment
```
Docker Compose → Rust container + Database container + Nginx proxy
```

## Technology Stack

### Backend
- **Language:** Rust
- **Framework:** Axum (web framework)
- **Database:** SQLite (rusqlite)
- **Async Runtime:** Tokio
- **Serialization:** Serde
- **Logging:** Tracing

### Frontend
- **Language:** Vanilla JavaScript
- **Styling:** CSS3
- **No frameworks** (intentional for simplicity)

### DevOps
- **Containerization:** Docker
- **Version Control:** Git
- **CI/CD:** GitHub Actions

## Future Enhancements

### Planned Features
- WebSocket support for real-time updates
- Multiplayer scenarios
- Advanced AI opponents
- Integration with real SIEM systems
- Mobile responsive design
- Advanced reporting and analytics
- Team collaboration features
- Custom scenario editor

### Technical Improvements
- Database migration to PostgreSQL
- Redis for session management
- Message queue for event processing
- Advanced caching layer
- Performance monitoring
- Advanced security features