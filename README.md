HALON

HALON is a portable Windows diagnostic, evidence reconstruction, knowledge retrieval, and reasoning system designed to help answer a simple question:

What actually happened on this Windows machine, and what does the available evidence support?

HALON collects Windows telemetry, reconstructs deterministic relationships, packages the resulting evidence, indexes it locally for semantic retrieval, and allows a local reasoning model to answer natural-language questions over that evidence.

The project is intentionally built around a strict separation between:

Evidence
    ↓
Knowledge
    ↓
Reasoning

The goal is not to pass raw logs directly into an LLM and hope for a plausible explanation.

The goal is to preserve a defensible chain from machine evidence to retrieved facts to model reasoning.

Current Architecture

HALON currently operates as a connected local pipeline:

Windows
   ↓
HALON.ps1
Evidence Engine
   ↓
HALON.py
Evidence Packager
   ↓
evidence-payload-v1.json
   ↓
Halon.KnowledgeEngine.py
Knowledge Engine
   ↓
Local LanceDB evidence store
   ↑
Halon.ReasoningEngine.py
Reasoning Engine
   ↑
Human question
   ↓
Qwen3 local model
   ↓
Grounded operator answer

The current PoC has been tested end to end using fresh Windows evidence collected from the host, packaged into a canonical payload, ingested into the Knowledge Engine, retrieved through natural-language queries, and reasoned over by a local Qwen3 model running with GPU offload.

Evidence Engine

The Evidence Engine is responsible for collecting, normalizing, reconstructing, correlating, and exporting deterministic Windows evidence.

The main entry point is:

src/HALON.ps1

HALON currently collects or reconstructs:

Windows system information

Disk information

Service state

Windows System and Application event evidence

Critical, error, warning, lifecycle, hardware, storage, and application events

Windows boot and event chronology

Security logon and logoff events

Current Windows session state

Windows interactive session lifecycle

Historical process creation events using Security Event 4688

Process trees

Process lineages

Process execution security context

Process-to-logon-context relationships

Process-to-Windows-session relationships

Event-to-process relationships when supported by the underlying event evidence

Incident windows and surrounding evidence

Session-to-incident relationships

Identity-to-incident relationships

Evidence summaries

Event recurrence summaries

Collection capability information

Agent performance diagnostics

The Evidence Engine does not assign root cause, intent, responsibility, blame, or inferred relevance.

Evidence Philosophy

HALON separates observed evidence from interpretation.

The Evidence Engine preserves what Windows recorded and what HALON can deterministically establish from that evidence.

For example:

A process creation event establishes that Windows recorded a process being created.

A matching Logon ID can associate that process with a Windows security context.

A matching SID can establish identity continuity across different event representations.

A session interval can establish that a Windows session existed at a particular time.

A parent process record can establish a recorded process relationship.

A deterministic event-to-process correlation can establish a relationship supported by the available identifiers and timing.

Temporal proximity alone does not establish causality.

Correlation does not establish human intent.

HALON also preserves evidence gaps explicitly.

For example:

[]

means HALON successfully evaluated that evidence source or relationship and found no matching records.

That is different from:

Evidence unavailable

which may result from permissions, disabled auditing, missing logs, missing artifacts, insufficient historical coverage, or unsupported event schemas.

HALON treats those states differently because:

No matching evidence is not the same as unavailable evidence.

Evidence Collection and Packaging

Each HALON collection creates a dedicated run directory beneath:

output/

For example:

output/
└── WADESYSTEM_20260902_154217/

The run directory is the unit of evidence for that collection.

HALON.ps1 performs the collection and deterministic reconstruction stages, then passes the exact run directory to:

src/HALON.py

HALON does not search for or guess which output directory is the latest.

The packager validates and combines the completed artifacts into:

evidence-payload-v1.json

The payload preserves evidence, relationships, reconstructions, summaries, collection capabilities, provenance, metadata, relationship counts, and agent diagnostics.

The exact payload path is then passed directly to the Knowledge Engine.

Generated Evidence

A complete HALON collection currently produces 24 canonical artifacts:

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
process-lineage.json
process-logon-contexts.json
process-execution-contexts.json
event-process-correlations.json

performance.json

These artifacts represent separate layers of collected, normalized, reconstructed, correlated, summarized, and provenance-aware evidence.

The output/ directory is excluded from source control because generated diagnostic evidence may contain usernames, security identifiers, process execution history, machine information, Windows event data, session information, and other potentially sensitive host evidence.

Process Evidence

When Windows Process Creation auditing is available, HALON collects Security Event 4688.

This allows HALON to preserve evidence such as:

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

HALON reconstructs process lineage from those records and can correlate the process with its Windows security context.

HALON does not interpret this as proof that a human manually launched an application.

The defensible statement is:

Windows recorded the process being created under the associated security context.

This distinction keeps HALON useful for interactive users, service accounts, automation accounts, scheduled tasks, scripts, system processes, and other unattended execution contexts.

Identity and Session Reconstruction

Windows may represent the same account differently across evidence sources.

HALON preserves identifiers such as:

User SID
Logon ID
Security Record ID
Session ID

so relationships do not have to depend entirely on display names.

HALON also distinguishes between a Security logon context and an actual Windows interactive session.

Security Event 4624 represents a successful logon context, but one interactive Windows session may generate multiple security logons.

HALON therefore reconstructs Windows session intervals separately.

Example:

User: WADESYSTEM\hurst
Session ID: 1
Session Start: 09/02/2026 09:13:36
Session End: Open
State: OpenAtCollectionEnd

This prevents HALON from incorrectly treating every Windows security logon as a separate desktop session.

Incident Reconstruction

HALON can reconstruct incident context around supported lifecycle evidence.

For each detected incident, HALON can preserve:

Incident type

Incident anchor time

Event logging time

Events before the incident

Events after the incident

Relative event timing

Boot-session context

Event recurrence

Windows-session evidence

Security identity evidence

Evidence coverage limitations

HALON explicitly distinguishes between:

Evidence found
Evidence not found
Evidence unavailable
Evidence outside the collection window

This prevents missing telemetry from being interpreted as proof that an activity did not occur.

Event and Process Correlation

HALON includes deterministic infrastructure for correlating supported Windows events with historical process execution.

The evidence chain can look like:

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

Process correlation is designed to account for Windows PID reuse.

A PID match alone is not sufficient when stronger evidence is available.

HALON can consider evidence such as:

Process ID
+
Process Name
+
Process Creation Time
+
Event Time
+
Logon ID

to establish a stronger relationship.

Event-to-process support is expanded only where the Windows event schema provides defensible process references.

Knowledge Engine

The Knowledge Engine is implemented in:

src/knowledge/Halon.KnowledgeEngine.py

It currently has two responsibilities:

1. Organize HALON evidence
2. Retrieve relevant deterministic evidence from natural language

The Knowledge Engine uses:

BAAI/bge-small-en-v1.5

for local semantic embeddings and:

LanceDB

as the local embedded vector database.

No external vector service is required.

HALON Evidence Families

The current Knowledge Engine contains 24 searchable HALON evidence families, including:

windowsSessions
processes
windowsEvents
identityEvents
currentSessions
windowsSessionEvents
services
identitySessions
system
disks

eventToProcess
processToParent
processToLogon
processToWindowsSession

evidenceSummary
eventSummary
processEvidenceCapability

timeline
processLineages
processExecutionContexts

incidents
incidentContexts
incidentIdentities
windowsSessionsAtIncident

Each searchable record preserves:

sourceType
family
searchText
metadata
originalRecord
embedding vector

The semantic text exists to make the evidence findable.

The original structured HALON record remains the factual source.

Semantic retrieval finds evidence. HALON evidence establishes facts.

Family Catalog

HALON does not search every evidence record for every question.

The Knowledge Engine maintains a semantic Family Catalog describing what each evidence family contains.

A question such as:

Who was logged into this machine?

can first retrieve:

windowsSessions
currentSessions

The Knowledge Engine then performs deeper retrieval only within those selected evidence families.

Retrieval Completeness

Semantic top-N retrieval is useful for finding relevant records, but a top-N result must never be mistaken for a complete enumeration.

HALON therefore distinguishes between semantic retrieval and deterministic enumeration.

For example:

What PowerShell activity occurred on this machine?

HALON can:

Select the processes family
        ↓
Scan the complete process evidence shelf
        ↓
Find every exact PowerShell process match
        ↓
Calculate deterministic counts and aggregates
        ↓
Provide a bounded set of supporting records to the model

In a tested collection containing 5,815 process records, HALON deterministically identified 52 PowerShell process records without sending all 52 full JSON records into the reasoning model context.

This preserves the distinction between:

Complete deterministic result

and:

Bounded model context

HALON Metadata and Provenance

Not everything stored in the Knowledge Engine is machine diagnostic evidence.

HALON separately preserves metadata including:

payloadMetadata
sourceManifest
artifactIndex
relationshipSummary
agentPerformance

These records are stored as:

HALON_METADATA

rather than:

HALON_EVIDENCE

Agent performance information, for example, describes HALON execution behavior and is not treated as evidence about the investigated Windows host.

Reasoning Engine

The Reasoning Engine is implemented in:

src/reasoning/Halon.ReasoningEngine.py

The current local reasoning model is:

Qwen3-8B-Q4_K_M.gguf

running through llama-cpp-python with model layers offloaded to the GPU.

The Reasoning Engine does not query Windows directly, perform deterministic evidence reconstruction, or search LanceDB itself.

Instead:

Human question
    ↓
Reasoning Engine
    ↓
Knowledge Engine
    ↓
Relevant HALON evidence
    ↓
Reasoning Engine
    ↓
Operator answer

The current response contract is intentionally concise and operator-focused.

Example:

ANSWER
The user "hurst" was logged into the machine.

EVIDENCE
- WADESYSTEM\hurst had an active Session ID 1.
- The session started at 09/02/2026 09:13:36.

HALON avoids producing unnecessary report sections when the question does not require them.

Reasoning Boundaries

The Reasoning Engine is instructed to:

Answer the actual question first

Use only supplied HALON evidence for machine-specific factual claims

Ignore unrelated retrieved records

Avoid assigning undocumented technical meaning

Avoid inventing user intent

Avoid converting correlation into causation

State material evidence limitations briefly

Avoid unsupported hypotheses

Avoid exposing model scratch work

Prefer concise operator-facing answers

The intended division of responsibility is:

The model decides what evidence it wants. Deterministic code decides what the evidence actually says.

Current End-to-End PoC

HALON has now been tested as a complete local pipeline:

Windows
   ↓
HALON.ps1
   ↓
24 canonical evidence artifacts
   ↓
HALON.py
   ↓
evidence-payload-v1.json
   ↓
Knowledge Engine
   ↓
LanceDB
   ↓
Natural-language evidence retrieval
   ↓
Reasoning Engine
   ↓
Qwen3 GPU inference
   ↓
Concise grounded answer

Tested questions include:

What PowerShell activity occurred on this machine?

Who was logged into this machine?

Was process creation evidence available during this collection?

The current integration regression verifies:

Knowledge retrieval:       3/3
Enumeration completeness:  2/2

Regression Testing

Knowledge Engine regression:

cd C:\Dev\halon
.\Test-KnowledgeEngine.ps1

A complete Knowledge Engine rebuild can be tested with:

.\Test-KnowledgeEngine.ps1 -ForceRebuild

Knowledge → Reasoning integration:

.\Test-ReasoningKnowledge.ps1

Regression outputs are written beneath:

output/regression/

Audit Policy

HALON is designed to behave as an observer.

It does not automatically enable Windows auditing policies in order to create additional evidence.

For Process Creation evidence, HALON records both:

Current audit policy
Historical Event 4688 availability

These are intentionally separate.

HALON can use historical records without modifying the host configuration.

Authoritative Knowledge

The next major Knowledge Engine capability is a separate authoritative documentation shelf.

The intended architecture is:

KNOWLEDGE ENGINE
│
├── HALON_EVIDENCE
│      What happened on this machine?
│
├── HALON_METADATA
│      Where did this evidence come from?
│
└── AUTHORITATIVE_KNOWLEDGE
       What does the documented Windows behavior mean?

Authoritative knowledge will remain provenance-separated from machine evidence.

Initial sources are expected to include official Microsoft documentation covering:

Windows Event IDs

Event providers

Security auditing

Process creation

Windows sessions

Services

Storage

Hardware

Bugchecks

Windows Error Reporting

This will allow HALON to distinguish:

HALON observed X.

from:

Microsoft documentation states X means Y.

The Reasoning Engine can then combine those sources without confusing documentation with observed evidence.

Long-Term Vision

HALON is intended to evolve into a portable Windows diagnostic system capable of reconstructing and reasoning over chains such as:

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

This is particularly useful in environments where multiple users, service accounts, automation accounts, scheduled workloads, scripts, and unattended processes execute on the same Windows systems.

The goal is not simply to collect more logs.

The goal is to make Windows evidence:

Easier to collect
Easier to reconstruct
Easier to retrieve
Easier to reason about
Easier to defend

Project Status

HALON is an active proof of concept.

The current PoC has demonstrated:

Evidence collection          ✅
Evidence normalization       ✅
Identity reconstruction      ✅
Session reconstruction       ✅
Process reconstruction       ✅
Deterministic relationships  ✅
Evidence packaging           ✅
Local semantic indexing      ✅
Natural-language retrieval   ✅
Complete enumeration         ✅
Local GPU reasoning          ✅
Grounded operator answers    ✅

The next major development phase is authoritative Windows knowledge retrieval.

HALON is still under active development and should not yet be treated as a production incident-response or forensic platform.
