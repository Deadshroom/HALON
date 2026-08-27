# HALON

HALON is a portable Windows diagnostic and evidence collection tool designed to reconstruct system activity around incidents without modifying the system being investigated.

The project focuses on collecting, normalizing, and correlating Windows evidence that is often difficult for system administrators to reconstruct manually.

## Current Capabilities

HALON currently collects and reconstructs:

- Windows system information
- Disk information
- Service state
- Windows System and Application event evidence
- Critical, error, warning, lifecycle, hardware, storage, and application events
- Windows boot and event chronology
- Security logon and logoff events
- Windows interactive session lifecycle
- Historical process creation events using Security Event 4688
- Process parent/child information
- Process execution security context
- Process-to-logon-context correlation
- Incident windows and surrounding evidence
- Session-to-incident correlation
- Event-to-process correlation infrastructure

## Evidence Philosophy

HALON separates observed evidence from interpretation.

The Evidence Engine is intended to preserve and correlate objective Windows telemetry without assigning root cause, responsibility, or inferred relevance.

For example:

- A process creation event establishes that Windows recorded a process being created.
- A matching Logon ID can associate that process with a Windows security context.
- A matching SID can establish continuity when Windows represents the same account differently across event sources.
- A session interval can establish whether a Windows session existed at a particular time.
- A process parent can establish the recorded process relationship between two executions.
- Temporal proximity alone does not establish causality.

HALON preserves evidence gaps explicitly rather than treating missing evidence as proof that an event did not occur.

For example:

```text
[]
```

means that HALON successfully evaluated an evidence source or correlation and found no matching records.

This is different from evidence being unavailable because of permissions, disabled auditing, missing logs, or insufficient historical coverage.

## Current Architecture

The current implementation is a PowerShell prototype located at:

```text
src/HALON.ps1
```

The prototype is intentionally being developed as a working Evidence Engine before being modularized.

Generated evidence is written beneath:

```text
output/
```

The `output` directory is excluded from source control because generated diagnostic evidence may contain:

- Usernames
- Security identifiers (SIDs)
- Process execution history
- Machine information
- Windows event data
- Session information
- Other potentially sensitive system evidence

## Evidence Sources

HALON currently uses several native Windows evidence sources.

### Windows Event Logs

HALON collects diagnostic and lifecycle events from sources including:

- System
- Application
- Security
- Windows Terminal Services Local Session Manager

### Security Events

HALON currently uses Security events including:

- `4624` - Successful logon
- `4634` - Logoff
- `4647` - User initiated logoff
- `4688` - Process creation
- `4778` - Session reconnect
- `4779` - Session disconnect

### Windows Session Events

HALON uses the following events from:

```text
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
```

including:

- `21` - Session logon
- `23` - Session logoff
- `24` - Session disconnect
- `25` - Session reconnect

### Lifecycle Events

HALON currently recognizes Windows lifecycle events including:

- `41` - Kernel-Power unexpected restart
- `1001` - Bugcheck reporting
- `1074` - Planned shutdown or restart
- `6005` - Event Log service started
- `6006` - Event Log service stopped
- `6008` - Unexpected shutdown

## Process Evidence

When Windows Process Creation auditing is available, HALON collects Security Event `4688`.

This allows HALON to preserve evidence such as:

```text
Process Creation
    |
    +-- Timestamp
    +-- Process ID
    +-- Process executable
    +-- Parent Process ID
    +-- Parent executable
    +-- Subject SID
    +-- Subject Logon ID
    +-- Security record ID
```

HALON can then correlate the process creation event with the Security logon context associated with the same Logon ID.

For example:

```text
Security 4624
Account logon
Logon ID: 0x60481
        |
        v
Security 4688
Process created
Logon ID: 0x60481
        |
        v
notepad++.exe
PID: 21932
Parent: explorer.exe
```

HALON does not interpret this as proof that a human manually launched the application.

Instead, the defensible statement is:

> Windows recorded the process being created under the associated security context.

This distinction allows HALON to remain useful for interactive users, service accounts, scheduled tasks, automation accounts, scripts, and other execution contexts.

## Identity Correlation

Windows may represent the same account differently across event sources.

For example:

```text
MicrosoftAccount\user@example.com
```

and:

```text
COMPUTERNAME\user
```

may represent the same underlying account.

HALON preserves Windows identifiers such as:

```text
User SID
Logon ID
Security Record ID
```

so correlations do not have to depend entirely on display names.

This allows HALON to reconstruct relationships using the identifiers Windows itself recorded.

## Session Reconstruction

HALON distinguishes between Security logon contexts and actual Windows desktop or terminal sessions.

Security Event `4624` represents a successful logon context, but a single Windows user session may produce multiple security logons.

HALON therefore also collects Windows Terminal Services session lifecycle evidence to reconstruct session intervals such as:

```text
User: WADESYSTEM\user
Session ID: 1
Session Start: 08/27/2026 07:31:03
Session End: Open
State: OpenAtCollectionEnd
```

This distinction prevents HALON from incorrectly treating every Windows security logon as a separate interactive desktop session.

## Incident Reconstruction

HALON currently reconstructs unexpected shutdown incidents using Windows lifecycle evidence.

For each detected incident, HALON can retain:

- Incident occurrence time
- Event logging time
- Events before the incident
- Events after the incident
- Relative event timing
- Boot session context
- Event recurrence
- Windows session evidence
- Security identity evidence
- Evidence coverage limitations

HALON explicitly distinguishes between:

```text
Evidence found
Evidence not found
Evidence unavailable
Evidence outside the collection window
```

This prevents missing telemetry from being interpreted as proof that an activity did not occur.

## Event and Process Correlation

HALON includes infrastructure for correlating diagnostic events with historical process execution.

The intended evidence chain is:

```text
Application / System Event
        |
        v
Referenced Process
        |
        v
Historical Process Creation
        |
        v
Security Logon Context
        |
        v
Identity
```

Process correlation is designed to account for Windows PID reuse.

A PID match alone is not sufficient when stronger evidence is available.

HALON can consider evidence such as:

```text
Process ID
+
Process Name
+
Process Creation Time
+
Event Time
+
Logon ID
```

to establish a stronger deterministic relationship.

Event-to-process correlation support is currently being expanded one Windows event schema at a time.

## Generated Evidence

A HALON run currently produces artifacts including:

```text
system-info.json
disks.json
services.json
events.json
evidence-summary.json
event-summary.json
timeline.json
incident-context.json
incidents.json
manifest.json

identity-events.json
identity-sessions.json
incident-identities.json

current-sessions.json
windows-session-events.json
windows-sessions.json
windows-sessions-at-incident.json

process-evidence-capability.json
process-events.json
process-logon-contexts.json
event-process-correlations.json
```

These artifacts represent separate layers of collected, normalized, reconstructed, and correlated evidence.

## Audit Policy

HALON is intended to behave as an observer.

It does not automatically enable Windows auditing policies in order to collect additional evidence.

For Process Creation auditing, HALON records both:

```text
Current audit policy
Historical Event 4688 availability
```

These are intentionally treated separately.

For example, Process Creation auditing may currently be disabled while historical `4688` records still exist within the collection window.

HALON can use those historical records without modifying the host configuration.

## Project Direction

HALON is being developed toward a layered diagnostic architecture:

```text
Evidence Engine
      |
      v
Knowledge Engine
      |
      v
Reasoning Engine
```

### Evidence Engine

Collects, normalizes, reconstructs, and correlates deterministic Windows evidence.

The Evidence Engine should answer questions such as:

```text
What happened?
When did it happen?
What process was involved?
What created that process?
What security context executed it?
What Windows session existed at that time?
What evidence was available?
What evidence was missing?
```

It should not independently decide why an incident happened.

### Knowledge Engine

The planned Knowledge Engine will retrieve authoritative technical documentation relevant to observed evidence.

The intended knowledge sources include official Microsoft Windows documentation covering areas such as:

- Windows Event IDs
- Event providers
- Security auditing
- Process creation
- Windows sessions
- Services
- Storage
- Hardware
- Bugchecks
- Windows Error Reporting

This allows technical documentation to remain separate from evidence observed on the investigated machine.

### Reasoning Engine

A future local AI model will evaluate HALON evidence together with documentation retrieved by the Knowledge Engine.

The Reasoning Engine should distinguish between:

- Observations
- Correlations
- Hypotheses
- Supporting evidence
- Contradictory evidence
- Evidence gaps
- Insufficient evidence

The model should be capable of concluding that the available evidence is insufficient to establish root cause.

## Long-Term Vision

HALON is intended to evolve into a portable Windows diagnostic system capable of reconstructing chains such as:

```text
Identity
    |
    v
Logon Context
    |
    v
Windows Session
    |
    v
Process Execution
    |
    v
Process Tree
    |
    v
Application / System Event
    |
    v
Incident Context
```

This can be particularly useful in environments where multiple users, service accounts, automation accounts, or unattended workloads execute on the same Windows systems.

The goal is not simply to collect more logs.

The goal is to make Windows evidence easier to reconstruct, understand, and defend.

## Status

HALON is currently an early prototype under active development.

The current PowerShell implementation is being preserved as a working baseline before the Evidence Engine is modularized into separate collection, normalization, correlation, and export components.
````
