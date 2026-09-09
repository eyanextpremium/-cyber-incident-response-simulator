# API Documentation

## Overview

The Cyber Incident Response Simulator provides a RESTful API for managing simulation sessions, scenarios, incidents, and SOC operations.

## Base URL

```
http://localhost:8080/api
```

## Authentication

Currently, the API does not require authentication. This is intentional for the simulator environment but should be changed for production deployments.

## Response Format

All API responses return JSON with the following structure:

```json
{
  "data": { ... },
  "error": null
}
```

Error responses:

```json
{
  "data": null,
  "error": {
    "message": "Error description",
    "code": "ERROR_CODE"
  }
}
```

## Endpoints

### Health Check

#### GET /health
Check if the API is running.

**Response:**
```json
{
  "status": "ok",
  "service": "Cyber Incident Response Simulator",
  "version": "0.1.0"
}
```

### Sessions

#### POST /api/sessions
Create a new simulation session.

**Request Body:**
```json
{
  "scenario_id": "brute_force",
  "analyst_name": "John Doe"
}
```

**Response:**
```json
{
  "session_id": "uuid",
  "scenario_id": "brute_force",
  "analyst_name": "John Doe",
  "scenario": {
    "name": "Brute Force Attack",
    "difficulty": "beginner",
    "description": "...",
    "objective": "...",
    "time_limit_secs": 600,
    "hints": ["..."],
    "expected_actions": ["..."]
  },
  "started_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/sessions
List all sessions.

**Response:**
```json
{
  "sessions": [...],
  "count": 10
}
```

#### GET /api/sessions/{session_id}
Get details of a specific session.

**Response:**
```json
{
  "id": "uuid",
  "scenario_id": "brute_force",
  "analyst_name": "John Doe",
  "status": "active",
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": null,
  "score": null
}
```

### Scenarios

#### GET /api/scenarios
List all available scenarios.

**Response:**
```json
{
  "scenarios": [
    {
      "id": "brute_force",
      "name": "Brute Force Attack",
      "difficulty": "beginner",
      "category": "authentication",
      "description": "...",
      "objective": "...",
      "time_limit_secs": 600
    }
  ],
  "count": 12
}
```

### Events

#### GET /api/sessions/{session_id}/events
List all events for a session.

**Response:**
```json
{
  "events": [
    {
      "id": "uuid",
      "session_id": "uuid",
      "timestamp": "2024-01-01T00:00:00Z",
      "source": "authentication",
      "event_type": "login_attempt",
      "message": "...",
      "host": "server-01",
      "source_ip": "10.0.1.5",
      "destination_ip": null,
      "user_name": "admin",
      "raw_log": "...",
      "mitre_technique": "T1110",
      "is_malicious": true
    }
  ],
  "count": 150
}
```

### Alerts

#### GET /api/sessions/{session_id}/alerts
List all alerts for a session.

**Response:**
```json
{
  "alerts": [
    {
      "id": "uuid",
      "session_id": "uuid",
      "rule_id": "brute_force_detected",
      "title": "Brute Force Attack Detected",
      "description": "...",
      "severity": "high",
      "status": "new",
      "event_ids": ["uuid1", "uuid2"],
      "source": "detection_engine",
      "created_at": "2024-01-01T00:00:00Z",
      "acknowledged_at": null,
      "resolved_at": null
    }
  ],
  "count": 25
}
```

#### POST /api/sessions/{session_id}/alerts/{alert_id}/acknowledge
Acknowledge an alert.

**Response:**
```json
{
  "success": true,
  "alert_id": "uuid",
  "status": "acknowledged"
}
```

#### PUT /api/sessions/{session_id}/alerts/{alert_id}
Update alert status.

**Request Body:**
```json
{
  "status": "investigating"
}
```

**Valid statuses:** `acknowledged`, `investigating`, `resolved`, `false_positive`

### Incidents

#### GET /api/sessions/{session_id}/incidents
List all incidents for a session.

**Response:**
```json
{
  "incidents": [...],
  "count": 5
}
```

#### POST /api/sessions/{session_id}/incidents
Create a new incident.

**Request Body:**
```json
{
  "title": "SQL Injection Attack",
  "severity": "high",
  "description": "Potential SQL injection detected on web server",
  "scenario_id": "web_attack"
}
```

**Valid severities:** `low`, `medium`, `high`, `critical`

#### PUT /api/sessions/{session_id}/incidents/{incident_id}
Update incident status.

**Request Body:**
```json
{
  "status": "contained"
}
```

**Valid statuses:** `investigating`, `contained`, `eradicated`, `recovered`, `closed`

### Investigation

#### GET /api/sessions/{session_id}/timeline
Get attack timeline for a session.

**Response:**
```json
{
  "timeline": [
    {
      "timestamp": "2024-01-01T00:00:00Z",
      "event_type": "initial_access",
      "description": "...",
      "mitre_technique": "T1190",
      "severity": "high"
    }
  ],
  "count": 15
}
```

#### GET /api/sessions/{session_id}/investigation/summary
Get investigation summary.

**Response:**
```json
{
  "total_events": 150,
  "malicious_events": 45,
  "alerts_triggered": 25,
  "incidents_created": 3,
  "evidence_collected": 12,
  "attack_chain_stage": "lateral_movement"
}
```

#### GET /api/sessions/{session_id}/evidence
List collected evidence.

**Response:**
```json
{
  "evidence": [...],
  "count": 12
}
```

#### POST /api/sessions/{session_id}/evidence/collect
Auto-collect evidence.

**Response:**
```json
{
  "collected": 5,
  "evidence": [...]
}
```

### Response

#### POST /api/sessions/{session_id}/actions
Execute a response action.

**Request Body:**
```json
{
  "action_type": "isolate_host",
  "target": "10.0.1.10",
  "incident_id": "uuid",
  "details": "Isolating web server due to confirmed compromise"
}
```

**Valid action types:**
- `isolate_host` - Isolate a host from the network
- `block_ip` - Block an IP address
- `kill_process` - Kill a malicious process
- `disable_account` - Disable a user account
- `revoke_sessions` - Revoke user sessions
- `patch_vulnerability` - Apply security patch
- `restore_backup` - Restore from backup
- `collect_artifacts` - Collect forensic artifacts

**Response:**
```json
{
  "success": true,
  "action_id": "uuid",
  "action_type": "isolate_host",
  "target": "10.0.1.10",
  "details": "Host isolated successfully"
}
```

#### GET /api/sessions/{session_id}/actions
List all response actions.

**Response:**
```json
{
  "actions": [...],
  "count": 8
}
```

### Scoring

#### GET /api/sessions/{session_id}/score
Get current score for a session.

**Response:**
```json
{
  "id": "uuid",
  "session_id": "uuid",
  "detection_score": 85.5,
  "investigation_score": 72.0,
  "containment_score": 90.0,
  "recovery_score": 0.0,
  "total_score": 82.5,
  "time_elapsed_secs": 450,
  "calculated_at": "2024-01-01T00:07:30Z"
}
```

#### POST /api/sessions/{session_id}/finalize
Finalize session and calculate final score.

**Response:**
```json
{
  "session_id": "uuid",
  "metrics": {
    "detection_score": 85.5,
    "investigation_score": 72.0,
    "containment_score": 90.0,
    "recovery_score": 0.0,
    "total_score": 82.5,
    "time_elapsed_secs": 450
  },
  "ranking": {
    "tier": "Gold",
    "percentile": 85,
    "analyst_level": "Senior Analyst"
  }
}
```

### Assets

#### GET /api/assets
List all network assets.

**Response:**
```json
{
  "assets": [
    {
      "id": "asset-dc01",
      "hostname": "dc-server-01",
      "ip_address": "10.0.1.5",
      "asset_type": "server",
      "os": "Windows Server 2022",
      "criticality": "critical",
      "department": "IT",
      "status": "active"
    }
  ],
  "count": 10
}
```

### Statistics

#### GET /api/stats
Get global simulator statistics.

**Response:**
```json
{
  "total_events_generated": 1500,
  "total_alerts_fired": 250,
  "total_incidents_opened": 45
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `NOT_FOUND` | Resource not found |
| `BAD_REQUEST` | Invalid request parameters |
| `INTERNAL_ERROR` | Server error |
| `CONFLICT` | Resource conflict |

## Rate Limiting

Currently no rate limiting is implemented. Consider adding rate limiting for production deployments.

## WebSocket Support

The simulator uses HTTP polling for real-time updates. WebSocket support could be added for better real-time performance.