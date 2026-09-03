import argparse
import json
import re

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import lancedb
from sentence_transformers import SentenceTransformer


# ============================================================
# HALON KNOWLEDGE ENGINE
#
# Evidence remains separated into family-specific LanceDB tables.
#
# Evidence is organized into family-specific LanceDB tables.
#
# The Family Catalog is the first semantic retrieval layer.
# Natural-language questions are compared against catalog cards,
# then only the most relevant evidence shelves are searched.
#
# The Family Catalog remains the first semantic retrieval layer.
# A natural-language question is compared against catalog cards
# first, then only the most relevant evidence shelves are searched.
#
# The Family Catalog is semantic retrieval, not model reasoning.
# Qwen is not used to select evidence sources.
#
# The original HALON record remains the source of truth.
#
# No Qwen.
# No reasoning.
# No authoritative documentation yet.
# ============================================================


EMBEDDING_MODEL_NAME = "BAAI/bge-small-en-v1.5"

FAMILY_TABLES = {
    "windowsSessions":
        "halon_evidence_windows_sessions",

    "processes":
        "halon_evidence_processes",

    "windowsEvents":
        "halon_evidence_windows_events",

    "identityEvents":
        "halon_evidence_identity_events",

    "currentSessions":
        "halon_evidence_current_sessions",

    "windowsSessionEvents":
        "halon_evidence_windows_session_events",

    "services":
        "halon_evidence_services",

    "identitySessions":
        "halon_evidence_identity_sessions",

    "system":
        "halon_evidence_system",

    "disks":
        "halon_evidence_disks",

    "eventToProcess":
        "halon_evidence_event_to_process",

    "processToParent":
        "halon_evidence_process_to_parent",

    "processToLogon":
        "halon_evidence_process_to_logon",

    "processToWindowsSession":
        "halon_evidence_process_to_windows_session",

    "evidenceSummary":
        "halon_evidence_summary",

    "eventSummary":
        "halon_event_summary",

    "processEvidenceCapability":
        "halon_process_evidence_capability",

    "timeline":
        "halon_evidence_timeline",

    "processLineages":
        "halon_evidence_process_lineages",

    "processExecutionContexts":
        "halon_evidence_process_execution_contexts",

    "incidents":
        "halon_evidence_incidents",

    "incidentContexts":
        "halon_evidence_incident_contexts",

    "incidentIdentities":
        "halon_evidence_incident_identities",

    "windowsSessionsAtIncident":
        "halon_evidence_windows_sessions_at_incident",
}


METADATA_TABLES = {
    "payloadMetadata":
        "halon_metadata_payload",

    "sourceManifest":
        "halon_metadata_source_manifest",

    "artifactIndex":
        "halon_metadata_artifact_index",

    "relationshipSummary":
        "halon_metadata_relationship_summary",

    "agentPerformance":
        "halon_metadata_agent_performance",
}


FAMILY_CATALOG_TABLE = (
    "halon_evidence_family_catalog"
)


FAMILY_CATALOG = {
    "windowsSessions": (
        "HALON reconstructed Windows user sessions and machine "
        "usage by users. This family answers questions about who "
        "used or logged into the computer, reconstructed session "
        "start and end times, session state, local or remote "
        "session sources, and historical Windows user sessions."
    ),

    "processes": (
        "HALON observed Windows process creation and executable "
        "activity. This family answers questions about programs "
        "that ran, executable launches, PowerShell activity, "
        "command shells, process IDs, parent and child processes, "
        "process ownership or execution identity, and process "
        "execution timing."
    ),

    "windowsEvents": (
        "HALON observed Windows Event Log activity. This family "
        "answers questions about errors, warnings, critical "
        "events, crashes, bugchecks, unexpected shutdowns, "
        "service failures, hardware or system events, event IDs, "
        "providers, event messages, and other Windows event-log "
        "observations."
    ),

    "identityEvents": (
        "HALON observed Windows security identity events. This "
        "family answers questions about logons, logoffs, user "
        "identity activity, logon IDs, logon types, usernames, "
        "domains, security identifiers, reconnect or disconnect "
        "identity context, and historical authentication activity."
    ),

    "currentSessions": (
        "HALON current Windows session snapshot. This family "
        "answers questions about users who were logged on when "
        "HALON collected evidence, current or active sessions, "
        "session names and IDs, session state, idle time, and "
        "observed logon time at collection."
    ),

    "windowsSessionEvents": (
        "HALON historical Windows session lifecycle events. This "
        "family answers questions about session logon, session "
        "logoff, session disconnect, session reconnect, session "
        "IDs, session users, source addresses, and Terminal "
        "Services Local Session Manager activity."
    ),

    "services": (
        "HALON observed Windows service state. This family answers "
        "questions about installed or observed services, service "
        "names and display names, running or stopped state, and "
        "service startup type."
    ),

    "identitySessions": (
        "HALON deterministic reconstructed interactive security "
        "identity sessions derived from Windows Security logon and "
        "logoff evidence. This family answers questions about "
        "interactive identity session intervals, logon IDs, logon "
        "types, session duration, open or closed security sessions, "
        "and the Security log records that begin or end a session."
    ),

    "system": (
        "HALON observed host system information. This family answers "
        "questions about the computer name, manufacturer, hardware "
        "model, Windows operating system version and build, CPU, "
        "physical memory, last boot time, and whether HALON was "
        "running with administrator privileges."
    ),

    "disks": (
        "HALON observed logical disk and storage volume information. "
        "This family answers questions about drive letters, volume "
        "names, file systems, drive types, total disk size, free "
        "space, and storage volumes present on the machine."
    ),

    "eventToProcess": (
        "HALON deterministic Windows-event-to-process relationships. "
        "This family answers questions about which historical process "
        "a Windows event explicitly referenced or was correlated to, "
        "the event record and provider, the referenced process ID or "
        "name, matched historical process evidence, elapsed process "
        "age at the event, and the deterministic evidence basis for "
        "the event-to-process match."
    ),

    "processToParent": (
        "HALON deterministic direct process parent-child relationships. "
        "This family answers questions about which direct parent process "
        "HALON linked to a child process, child and parent process IDs "
        "and names, their Security event record identifiers, and the "
        "deterministic evidence basis for recorded process ancestry."
    ),

    "processToLogon": (
        "HALON deterministic process-to-security-logon relationships. "
        "This family answers questions about which Windows security "
        "logon identity or logon session a process executed under, "
        "including process identifiers, logon Security record ID, "
        "identity, SID, logon type, logon time, and evidence basis."
    ),

    "processToWindowsSession": (
        "HALON deterministic process-to-Windows-user-session "
        "relationships. This family answers questions about which "
        "reconstructed Windows user session a process occurred within, "
        "including process identifiers, session ID, session user, "
        "session logon record, session start and end, source address, "
        "and deterministic evidence basis."
    ),

    "evidenceSummary": (
        "HALON deterministic evidence-category summary. This family "
        "answers questions about what categories of Windows evidence "
        "HALON observed and how many records were collected in each "
        "category."
    ),

    "eventSummary": (
        "HALON deterministic recurring-event summary. This family "
        "answers questions about repeated Windows event patterns, "
        "including provider, event ID, event level, and occurrence "
        "count."
    ),

    "processEvidenceCapability": (
        "HALON process-evidence collection capability. This family "
        "answers questions about whether Windows Process Creation "
        "auditing was enabled, the detected audit policy, historical "
        "Security Event 4688 collection status, collection errors, "
        "and how many process-creation events were available."
    ),

    "timeline": (
        "HALON deterministic reconstructed chronological event "
        "timeline for the collected evidence window. This family "
        "answers questions about event order, boot-session context, "
        "event timing, shutdown or restart anchors, recurrence, and "
        "the chronological sequence of observed Windows events."
    ),

    "processLineages": (
        "HALON deterministic process lineage reconstruction. This "
        "family answers questions about process ancestry, parent "
        "and ancestor processes, process chains, lineage depth, "
        "how a process was launched, and the evidence connecting "
        "a process to its parent lineage."
    ),

    "processExecutionContexts": (
        "HALON deterministic process execution context "
        "reconstruction. This family answers questions about a "
        "process and its lineage together with security logon "
        "identity, Windows session matches, execution user "
        "context, session context, and evidence basis."
    ),

    "incidents": (
        "HALON deterministic reconstructed incident records and "
        "focused incident windows centered on an incident anchor. "
        "This family answers questions about which incidents HALON "
        "reconstructed, incident type, anchor time, the bounded "
        "incident window, events inside that defined window, "
        "incident-window membership, and incident-associated "
        "diagnostic artifacts."
    ),

    "incidentContexts": (
        "HALON deterministic full-collection chronological context "
        "relative to an incident anchor. This family answers "
        "questions about what happened before and after an incident "
        "across the broader collected timeline, PRE_INCIDENT, "
        "INCIDENT, and POST_INCIDENT classification, boot-session "
        "context, and whether each event falls inside the focused "
        "incident window."
    ),

    "incidentIdentities": (
        "HALON deterministic identity-to-incident correlation. "
        "This family answers questions about users, identities, "
        "security logon sessions, and authentication sessions "
        "that overlapped an incident time, including the evidence "
        "basis and identity evidence coverage."
    ),

    "windowsSessionsAtIncident": (
        "HALON deterministic Windows-session-to-incident "
        "correlation. This family answers questions about Windows "
        "user sessions that overlapped an incident, users present "
        "at incident time, session coverage, local or remote "
        "session source, and the evidence basis for the match."
    ),
}


# ============================================================
# GENERIC HELPERS
# ============================================================


def first_value(
    record: dict[str, Any],
    *names: str,
) -> Any:

    for name in names:

        value = record.get(
            name
        )

        if value not in (
            None,
            "",
        ):
            return value

    return None


def clean_text(
    value: Any,
) -> str:

    if value is None:
        return ""

    return " ".join(
        str(
            value
        ).split()
    )


def parse_halon_timestamp(
    value: Any,
) -> str:

    if value in (
        None,
        "",
    ):
        return ""

    text = str(
        value
    ).strip()

    if not text:
        return ""

    # --------------------------------------------------------
    # POWERSHELL / .NET JSON DATE
    # --------------------------------------------------------

    if (
        text.startswith(
            "/Date("
        )
        and text.endswith(
            ")/"
        )
    ):

        inner = text[
            6:
            -2
        ]

        # HALON payloads currently contain plain epoch
        # milliseconds, but tolerate an optional timezone suffix.
        match_text = inner

        for separator in (
            "+",
            "-",
        ):

            position = match_text.find(
                separator,
                1,
            )

            if position != -1:

                match_text = match_text[
                    :position
                ]

                break

        try:

            milliseconds = int(
                match_text
            )

            return (
                datetime.fromtimestamp(
                    milliseconds / 1000,
                    tz=timezone.utc,
                )
                .isoformat()
            )

        except ValueError:

            return text

    # --------------------------------------------------------
    # ISO 8601
    # --------------------------------------------------------

    iso_text = text

    if iso_text.endswith(
        "Z"
    ):

        iso_text = (
            iso_text[:-1]
            + "+00:00"
        )

    try:

        parsed = datetime.fromisoformat(
            iso_text
        )

        return parsed.isoformat()

    except ValueError:

        pass

    # --------------------------------------------------------
    # HALON / WINDOWS TIMESTAMP FORMATS
    # --------------------------------------------------------

    formats = (
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
    )

    for format_string in formats:

        try:

            parsed = datetime.strptime(
                text,
                format_string,
            )

            return parsed.isoformat()

        except ValueError:

            continue

    # Preserve the original observed value if HALON encounters
    # an unfamiliar timestamp representation.
    return text


def get_record_timestamp(
    record: dict[str, Any],
) -> str:

    value = first_value(
        record,
        "OccurrenceTime",
        "LoggedTime",
        "TimeCreated",
        "ProcessTime",
        "LogonTime",
        "SessionStart",
        "SessionEnd",
        "EventTime",
        "AnchorTime",
        "IncidentTime",
        "WindowStart",
        "CollectionStart",
        "CollectionEnd",
        "LastBootTime",
        "eventTime",
        "logonTime",
        "sessionStart",
        "time",
    )

    return parse_halon_timestamp(
        value
    )


def get_record_identity(
    record: dict[str, Any],
) -> str:

    identity = first_value(
        record,
        "SubjectIdentity",
        "Identity",
        "User",
        "UserName",
        "TargetIdentity",
        "sessionUser",
        "EventUser",
        "logonIdentity",
    )

    return clean_text(
        identity
    )


def get_record_id(
    record: dict[str, Any],
) -> str:

    record_id = first_value(
        record,
        "RecordId",
        "SecurityRecordId",
        "recordId",
        "LogonRecordId",
        "ProcessSecurityRecordId",
        "eventRecordId",
        "processSecurityRecordId",
        "childProcessSecurityRecordId",
    )

    return clean_text(
        record_id
    )


# ============================================================
# SEARCHABLE REPRESENTATIONS
#
# Search text is only a retrieval aid.
# The original HALON JSON record is preserved separately.
# ============================================================


def build_windows_session_search_text(
    record: dict[str, Any],
) -> str:

    user = first_value(
        record,
        "User",
        "UserName",
        "Identity",
        "sessionUser",
    )

    session_id = first_value(
        record,
        "SessionId",
        "SessionID",
    )

    source_address = first_value(
        record,
        "SourceAddress",
    )

    session_start = first_value(
        record,
        "SessionStart",
        "LogonTime",
    )

    session_end = first_value(
        record,
        "SessionEnd",
    )

    state = first_value(
        record,
        "State",
        "Status",
    )

    parts = [
        (
            "HALON reconstructed Windows user session. "
            "This record represents observed user session "
            "activity on this machine."
        ),
    ]

    if user is not None:

        parts.append(
            f"User: {clean_text(user)}."
        )

    if session_id is not None:

        parts.append(
            f"Session ID: {clean_text(session_id)}."
        )

    if source_address is not None:

        parts.append(
            f"Source address: {clean_text(source_address)}."
        )

    if session_start is not None:

        parts.append(
            f"Session started: {clean_text(session_start)}."
        )

    if session_end is not None:

        parts.append(
            f"Session ended: {clean_text(session_end)}."
        )

    if state is not None:

        parts.append(
            f"Session state: {clean_text(state)}."
        )

    return " ".join(
        parts
    )


def build_process_search_text(
    record: dict[str, Any],
) -> str:

    process_name = first_value(
        record,
        "ProcessName",
        "processName",
        "Name",
        "NewProcessName",
    )

    process_id = first_value(
        record,
        "ProcessId",
        "ProcessIdDecimal",
        "processId",
        "NewProcessId",
    )

    parent_process = first_value(
        record,
        "ParentProcessName",
        "ParentProcess",
        "CreatorProcessName",
    )

    parent_process_id = first_value(
        record,
        "ParentProcessId",
        "ParentProcessIdDecimal",
        "CreatorProcessId",
    )

    command_line = first_value(
        record,
        "CommandLine",
        "ProcessCommandLine",
    )

    identity = first_value(
        record,
        "SubjectIdentity",
        "Identity",
        "User",
        "UserName",
        "TargetIdentity",
    )

    timestamp = first_value(
        record,
        "ProcessTime",
        "TimeCreated",
        "OccurrenceTime",
        "LoggedTime",
    )

    record_id = first_value(
        record,
        "RecordId",
        "SecurityRecordId",
        "recordId",
    )

    parts = [
        (
            "HALON Windows process activity record. "
            "This record represents executable or process "
            "activity observed on this machine."
        ),
    ]

    if process_name is not None:

        parts.append(
            f"Process name: {clean_text(process_name)}."
        )

    if process_id is not None:

        parts.append(
            f"Process ID: {clean_text(process_id)}."
        )

    if parent_process is not None:

        parts.append(
            f"Parent process: {clean_text(parent_process)}."
        )

    if parent_process_id is not None:

        parts.append(
            f"Parent process ID: {clean_text(parent_process_id)}."
        )

    if identity is not None:

        parts.append(
            f"Identity: {clean_text(identity)}."
        )

    if command_line is not None:

        parts.append(
            f"Command line: {clean_text(command_line)}."
        )

    if timestamp is not None:

        parts.append(
            f"Observed time: {clean_text(timestamp)}."
        )

    if record_id is not None:

        parts.append(
            f"Record ID: {clean_text(record_id)}."
        )

    return " ".join(
        parts
    )


def build_windows_event_search_text(
    record: dict[str, Any],
) -> str:

    provider = first_value(
        record,
        "Provider",
        "ProviderName",
        "eventProvider",
    )

    event_id = first_value(
        record,
        "EventID",
        "EventId",
        "eventId",
    )

    level = first_value(
        record,
        "Level",
        "LevelDisplayName",
        "Severity",
    )

    category = first_value(
        record,
        "Category",
    )

    message = first_value(
        record,
        "Message",
        "RenderedDescription",
        "Description",
    )

    timestamp = first_value(
        record,
        "OccurrenceTime",
        "LoggedTime",
        "TimeCreated",
        "EventTime",
    )

    record_id = first_value(
        record,
        "RecordId",
        "recordId",
    )

    log_name = first_value(
        record,
        "LogName",
        "Channel",
    )

    parts = [
        (
            "HALON Windows event record. "
            "This record represents Windows event-log activity, "
            "including errors, warnings, failures, informational "
            "events, and other system observations."
        ),
    ]

    if provider is not None:

        parts.append(
            f"Provider: {clean_text(provider)}."
        )

    if event_id is not None:

        parts.append(
            f"Event ID: {clean_text(event_id)}."
        )

    if level is not None:

        parts.append(
            f"Level: {clean_text(level)}."
        )

    if category is not None:

        parts.append(
            f"Category: {clean_text(category)}."
        )

    if log_name is not None:

        parts.append(
            f"Log: {clean_text(log_name)}."
        )

    if message is not None:

        parts.append(
            f"Message: {clean_text(message)}."
        )

    if timestamp is not None:

        parts.append(
            f"Observed time: {clean_text(timestamp)}."
        )

    if record_id is not None:

        parts.append(
            f"Record ID: {clean_text(record_id)}."
        )

    return " ".join(
        parts
    )


def build_identity_event_search_text(
    record: dict[str, Any],
) -> str:

    action = first_value(
        record,
        "Action",
    )

    identity = first_value(
        record,
        "Identity",
        "User",
        "UserName",
    )

    user_name = first_value(
        record,
        "UserName",
    )

    domain = first_value(
        record,
        "Domain",
    )

    user_sid = first_value(
        record,
        "UserSid",
    )

    logon_id = first_value(
        record,
        "LogonId",
    )

    logon_type = first_value(
        record,
        "LogonType",
    )

    session_name = first_value(
        record,
        "SessionName",
    )

    client_name = first_value(
        record,
        "ClientName",
    )

    client_address = first_value(
        record,
        "ClientAddress",
    )

    timestamp = first_value(
        record,
        "TimeCreated",
        "OccurrenceTime",
        "LoggedTime",
    )

    record_id = first_value(
        record,
        "RecordId",
        "recordId",
    )

    parts = [
        (
            "HALON Windows security identity event. "
            "This record represents observed logon, logoff, "
            "authentication, or identity session activity."
        ),
    ]

    if action is not None:

        parts.append(
            f"Action: {clean_text(action)}."
        )

    if identity is not None:

        parts.append(
            f"Identity: {clean_text(identity)}."
        )

    if user_name is not None:

        parts.append(
            f"User name: {clean_text(user_name)}."
        )

    if domain is not None:

        parts.append(
            f"Domain: {clean_text(domain)}."
        )

    if user_sid is not None:

        parts.append(
            f"User SID: {clean_text(user_sid)}."
        )

    if logon_id is not None:

        parts.append(
            f"Logon ID: {clean_text(logon_id)}."
        )

    if logon_type is not None:

        parts.append(
            f"Logon type: {clean_text(logon_type)}."
        )

    if session_name is not None:

        parts.append(
            f"Session name: {clean_text(session_name)}."
        )

    if client_name is not None:

        parts.append(
            f"Client name: {clean_text(client_name)}."
        )

    if client_address is not None:

        parts.append(
            f"Client address: {clean_text(client_address)}."
        )

    if timestamp is not None:

        parts.append(
            f"Observed time: {clean_text(timestamp)}."
        )

    if record_id is not None:

        parts.append(
            f"Record ID: {clean_text(record_id)}."
        )

    return " ".join(
        parts
    )


def build_current_session_search_text(
    record: dict[str, Any],
) -> str:

    user_name = first_value(
        record,
        "UserName",
        "User",
        "Identity",
    )

    session_name = first_value(
        record,
        "SessionName",
    )

    session_id = first_value(
        record,
        "SessionId",
        "SessionID",
    )

    state = first_value(
        record,
        "State",
        "Status",
    )

    idle_time = first_value(
        record,
        "IdleTime",
    )

    logon_time = first_value(
        record,
        "LogonTime",
        "SessionStart",
    )

    parts = [
        (
            "HALON current Windows session snapshot. "
            "This record represents a user session observed "
            "as present when HALON collected evidence."
        ),
    ]

    if user_name is not None:

        parts.append(
            f"User: {clean_text(user_name)}."
        )

    if session_name is not None:

        parts.append(
            f"Session name: {clean_text(session_name)}."
        )

    if session_id is not None:

        parts.append(
            f"Session ID: {clean_text(session_id)}."
        )

    if state is not None:

        parts.append(
            f"Session state: {clean_text(state)}."
        )

    if idle_time is not None:

        parts.append(
            f"Idle time: {clean_text(idle_time)}."
        )

    if logon_time is not None:

        parts.append(
            f"Logon time: {clean_text(logon_time)}."
        )

    return " ".join(
        parts
    )


def build_windows_session_event_search_text(
    record: dict[str, Any],
) -> str:

    action = first_value(
        record,
        "Action",
    )

    user = first_value(
        record,
        "User",
        "UserName",
        "Identity",
    )

    session_id = first_value(
        record,
        "SessionId",
        "SessionID",
    )

    source_address = first_value(
        record,
        "SourceAddress",
        "Address",
        "ClientAddress",
    )

    event_id = first_value(
        record,
        "EventID",
        "EventId",
    )

    provider = first_value(
        record,
        "Provider",
        "ProviderName",
    )

    message = first_value(
        record,
        "Message",
        "Description",
    )

    timestamp = first_value(
        record,
        "TimeCreated",
        "OccurrenceTime",
        "LoggedTime",
    )

    record_id = first_value(
        record,
        "RecordId",
        "recordId",
    )

    parts = [
        (
            "HALON Windows session lifecycle event. "
            "This record represents session logon, logoff, "
            "disconnect, or reconnect activity."
        ),
    ]

    if action is not None:

        parts.append(
            f"Action: {clean_text(action)}."
        )

    if user is not None:

        parts.append(
            f"User: {clean_text(user)}."
        )

    if session_id is not None:

        parts.append(
            f"Session ID: {clean_text(session_id)}."
        )

    if source_address is not None:

        parts.append(
            f"Source address: {clean_text(source_address)}."
        )

    if event_id is not None:

        parts.append(
            f"Event ID: {clean_text(event_id)}."
        )

    if provider is not None:

        parts.append(
            f"Provider: {clean_text(provider)}."
        )

    if message is not None:

        parts.append(
            f"Message: {clean_text(message)}."
        )

    if timestamp is not None:

        parts.append(
            f"Observed time: {clean_text(timestamp)}."
        )

    if record_id is not None:

        parts.append(
            f"Record ID: {clean_text(record_id)}."
        )

    return " ".join(
        parts
    )


def build_service_search_text(
    record: dict[str, Any],
) -> str:

    name = first_value(
        record,
        "Name",
        "ServiceName",
    )

    display_name = first_value(
        record,
        "DisplayName",
    )

    status = first_value(
        record,
        "Status",
        "State",
    )

    start_type = first_value(
        record,
        "StartType",
        "StartupType",
    )

    parts = [
        (
            "HALON Windows service state record. "
            "This record represents an observed Windows service "
            "and its service configuration or runtime state."
        ),
    ]

    if name is not None:

        parts.append(
            f"Service name: {clean_text(name)}."
        )

    if display_name is not None:

        parts.append(
            f"Display name: {clean_text(display_name)}."
        )

    if status is not None:

        parts.append(
            f"Status: {clean_text(status)}."
        )

    if start_type is not None:

        parts.append(
            f"Start type: {clean_text(start_type)}."
        )

    return " ".join(
        parts
    )



def build_identity_session_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic reconstructed interactive "
            "security identity session. This record describes "
            "an interval reconstructed from Windows Security "
            "logon and logoff evidence."
        ),
    ]

    fields = (
        ("Identity", "Identity"),
        ("Identity class", "IdentityClass"),
        ("User name", "UserName"),
        ("Domain", "Domain"),
        ("User SID", "UserSid"),
        ("Logon ID", "LogonId"),
        ("Logon type", "LogonType"),
        ("Session start", "SessionStart"),
        ("Session end", "SessionEnd"),
        ("Duration minutes", "DurationMinutes"),
        ("Session state", "State"),
        ("End reason", "EndReason"),
        ("Logon record ID", "LogonRecordId"),
        ("Logoff record ID", "LogoffRecordId"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_system_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON observed host system information. "
            "This record describes the machine hardware, "
            "Windows operating system, memory, boot time, "
            "and collection privilege context."
        ),
    ]

    fields = (
        ("Computer name", "ComputerName"),
        ("Manufacturer", "Manufacturer"),
        ("Model", "Model"),
        ("Operating system", "OS"),
        ("OS version", "OSVersion"),
        ("OS build", "OSBuild"),
        ("Last boot time", "LastBootTime"),
        ("CPU", "CPU"),
        ("RAM GB", "RAMGB"),
        ("Administrator", "Administrator"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_disk_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON observed logical disk and storage volume. "
            "This record describes a drive or volume present "
            "on the machine and its capacity information."
        ),
    ]

    fields = (
        ("Device ID", "DeviceID"),
        ("Volume name", "VolumeName"),
        ("File system", "FileSystem"),
        ("Drive type", "DriveType"),
        ("Size GB", "SizeGB"),
        ("Free GB", "FreeGB"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_event_to_process_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic Windows event to historical "
            "process relationship. This record establishes the "
            "process evidence HALON matched to a Windows event."
        ),
    ]

    fields = (
        ("Relationship", "relationship"),
        ("Event record ID", "eventRecordId"),
        ("Event time", "eventTime"),
        ("Event provider", "eventProvider"),
        ("Event ID", "eventId"),
        ("Referenced process ID", "referencedProcessId"),
        ("Referenced process name", "referencedProcessName"),
        ("Process Security record ID", "processSecurityRecordId"),
        ("Historical process name", "historicalProcessName"),
        ("Process age at event seconds", "processAgeAtEventSeconds"),
        ("Evidence basis", "evidenceBasis"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_process_to_parent_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic direct child process to parent "
            "process relationship. This record establishes recorded "
            "direct process ancestry."
        ),
    ]

    fields = (
        ("Relationship", "relationship"),
        (
            "Child process Security record ID",
            "childProcessSecurityRecordId",
        ),
        ("Child process ID", "childProcessId"),
        ("Child process name", "childProcessName"),
        (
            "Parent process Security record ID",
            "parentProcessSecurityRecordId",
        ),
        ("Parent process ID", "parentProcessId"),
        ("Parent process name", "parentProcessName"),
        ("Evidence basis", "evidenceBasis"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_process_to_logon_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic process to Windows security "
            "logon relationship. This record establishes the "
            "security logon context under which Windows recorded "
            "the process executing."
        ),
    ]

    fields = (
        ("Relationship", "relationship"),
        (
            "Process Security record ID",
            "processSecurityRecordId",
        ),
        ("Process ID", "processId"),
        ("Process name", "processName"),
        (
            "Logon Security record ID",
            "logonSecurityRecordId",
        ),
        ("Logon identity", "logonIdentity"),
        ("Logon user SID", "logonUserSid"),
        ("Logon type", "logonType"),
        ("Logon time", "logonTime"),
        ("Evidence basis", "evidenceBasis"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_process_to_windows_session_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic process to reconstructed Windows "
            "user session relationship. This record establishes "
            "the Windows session within which HALON placed the "
            "process."
        ),
    ]

    fields = (
        ("Relationship", "relationship"),
        (
            "Process Security record ID",
            "processSecurityRecordId",
        ),
        ("Process ID", "processId"),
        ("Process name", "processName"),
        ("Session ID", "sessionId"),
        ("Session user", "sessionUser"),
        (
            "Session logon record ID",
            "sessionLogonRecordId",
        ),
        ("Session start", "sessionStart"),
        ("Session end", "sessionEnd"),
        ("Source address", "sourceAddress"),
        ("Evidence basis", "evidenceBasis"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_evidence_summary_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic evidence-category summary. "
            "This record counts Windows evidence records in "
            "one HALON evidence category."
        ),
    ]

    category = record.get(
        "Category"
    )

    count = record.get(
        "Count"
    )

    if category not in (
        None,
        "",
    ):

        parts.append(
            f"Category: {clean_text(category)}."
        )

    if count not in (
        None,
        "",
    ):

        parts.append(
            f"Count: {clean_text(count)}."
        )

    return " ".join(
        parts
    )


def build_event_summary_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic recurring Windows event summary. "
            "This record groups matching event provider, event ID, "
            "and event level observations and preserves the count."
        ),
    ]

    fields = (
        ("Provider", "Provider"),
        ("Event ID", "EventID"),
        ("Level", "Level"),
        ("Count", "Count"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_process_evidence_capability_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON Windows Process Creation evidence capability. "
            "This record describes whether Security Event 4688 "
            "process-creation evidence was available to HALON and "
            "the audit-policy and collection state supporting it."
        ),
    ]

    fields = (
        ("Audit subcategory", "AuditSubcategory"),
        ("Current audit policy", "CurrentAuditPolicy"),
        (
            "Success auditing enabled",
            "SuccessAuditingEnabled",
        ),
        (
            "Audit policy detection error",
            "AuditPolicyDetectionError",
        ),
        ("Historical 4688 status", "Historical4688Status"),
        (
            "Historical 4688 events collected",
            "Historical4688EventsCollected",
        ),
        (
            "Historical 4688 collection error",
            "Historical4688CollectionError",
        ),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_timeline_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic reconstructed timeline event. "
            "This record preserves chronological event context "
            "and boot-session placement."
        ),
    ]

    fields = (
        ("Occurrence time", "OccurrenceTime"),
        ("Logged time", "LoggedTime"),
        ("Provider", "Provider"),
        ("Event ID", "EventID"),
        ("Level", "Level"),
        ("Category", "Category"),
        ("Anchor type", "AnchorType"),
        ("Boot session", "BootSessionId"),
        ("Event user", "EventUser"),
        ("Seconds since previous event", "SecondsSincePreviousEvent"),
        ("Occurrences in collection", "OccurrencesInCollection"),
        ("Message", "Message"),
        ("Record ID", "RecordId"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    return " ".join(
        parts
    )


def build_process_lineage_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic process lineage reconstruction. "
            "This record describes a process and its reconstructed "
            "parent and ancestor chain."
        ),
    ]

    fields = (
        ("Process time", "ProcessTime"),
        ("Process ID", "ProcessId"),
        ("Process name", "ProcessName"),
        ("Process security record ID", "ProcessSecurityRecordId"),
        ("Lineage node count", "LineageNodeCount"),
        ("Ancestor count", "AncestorCount"),
        ("Termination reason", "TerminationReason"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    lineage = record.get(
        "Lineage",
        []
    )

    if isinstance(
        lineage,
        list
    ):

        process_names = []
        identities = []
        evidence_bases = []

        for node in lineage:

            if not isinstance(
                node,
                dict
            ):
                continue

            process_name = node.get(
                "ProcessName"
            )

            if (
                process_name
                and process_name not in process_names
            ):

                process_names.append(
                    clean_text(
                        process_name
                    )
                )

            identity = node.get(
                "SubjectIdentity"
            )

            if (
                identity
                and identity not in identities
            ):

                identities.append(
                    clean_text(
                        identity
                    )
                )

            evidence_basis = node.get(
                "EvidenceBasisToParent"
            )

            if (
                evidence_basis
                and evidence_basis not in evidence_bases
            ):

                evidence_bases.append(
                    clean_text(
                        evidence_basis
                    )
                )

        if process_names:

            parts.append(
                "Lineage process names: "
                + "; ".join(
                    process_names
                )
                + "."
            )

        if identities:

            parts.append(
                "Lineage identities: "
                + "; ".join(
                    identities
                )
                + "."
            )

        if evidence_bases:

            parts.append(
                "Lineage evidence bases: "
                + "; ".join(
                    evidence_bases
                )
                + "."
            )

    return " ".join(
        parts
    )


def build_process_execution_context_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic process execution context "
            "reconstruction. This record combines process lineage "
            "with security logon and Windows session context."
        ),
    ]

    fields = (
        ("Process time", "ProcessTime"),
        ("Process ID", "ProcessId"),
        ("Process name", "ProcessName"),
        ("Process security record ID", "ProcessSecurityRecordId"),
        ("Lineage node count", "LineageNodeCount"),
        ("Ancestor count", "AncestorCount"),
        ("Termination reason", "TerminationReason"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    lineage = record.get(
        "ContextLineage",
        []
    )

    if isinstance(
        lineage,
        list
    ):

        process_names = []
        subject_identities = []
        logon_identities = []
        session_users = []
        evidence_bases = []

        for node in lineage:

            if not isinstance(
                node,
                dict
            ):
                continue

            for field, target in (
                ("ProcessName", process_names),
                ("SubjectIdentity", subject_identities),
                ("SecurityLogonIdentity", logon_identities),
                ("SecurityLogonEvidenceBasis", evidence_bases),
                ("WindowsSessionEvidenceBasis", evidence_bases),
                ("EvidenceBasisToParent", evidence_bases),
            ):

                value = node.get(
                    field
                )

                if (
                    value
                    and clean_text(value) not in target
                ):

                    target.append(
                        clean_text(
                            value
                        )
                    )

            sessions = node.get(
                "WindowsSessionMatches",
                []
            )

            if isinstance(
                sessions,
                list
            ):

                for session in sessions:

                    if not isinstance(
                        session,
                        dict
                    ):
                        continue

                    user = session.get(
                        "User"
                    )

                    if (
                        user
                        and clean_text(user) not in session_users
                    ):

                        session_users.append(
                            clean_text(
                                user
                            )
                        )

        if process_names:

            parts.append(
                "Context process names: "
                + "; ".join(
                    process_names
                )
                + "."
            )

        if subject_identities:

            parts.append(
                "Subject identities: "
                + "; ".join(
                    subject_identities
                )
                + "."
            )

        if logon_identities:

            parts.append(
                "Security logon identities: "
                + "; ".join(
                    logon_identities
                )
                + "."
            )

        if session_users:

            parts.append(
                "Windows session users: "
                + "; ".join(
                    session_users
                )
                + "."
            )

        if evidence_bases:

            parts.append(
                "Evidence bases: "
                + "; ".join(
                    evidence_bases
                )
                + "."
            )

    return " ".join(
        parts
    )


def build_incident_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic incident reconstruction. "
            "This record represents an incident window and the "
            "events deterministically placed around its anchor."
        ),
    ]

    fields = (
        ("Incident type", "IncidentType"),
        ("Anchor time", "AnchorTime"),
        ("Window start", "WindowStart"),
        ("Window end", "WindowEnd"),
        ("Event count", "EventCount"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    events = record.get(
        "Events",
        []
    )

    if isinstance(
        events,
        list
    ):

        providers = []
        event_ids = []
        categories = []
        phases = []
        anchor_types = []
        messages = []

        for event in events:

            if not isinstance(
                event,
                dict
            ):
                continue

            for field, target in (
                ("Provider", providers),
                ("EventID", event_ids),
                ("Category", categories),
                ("IncidentPhase", phases),
                ("AnchorType", anchor_types),
            ):

                value = event.get(
                    field
                )

                value_text = clean_text(
                    value
                )

                if (
                    value_text
                    and value_text not in target
                ):

                    target.append(
                        value_text
                    )

            message = clean_text(
                event.get(
                    "Message"
                )
            )

            if (
                message
                and message not in messages
                and len(messages) < 5
            ):

                messages.append(
                    message
                )

        for label, values in (
            ("Providers", providers),
            ("Event IDs", event_ids),
            ("Categories", categories),
            ("Incident phases", phases),
            ("Anchor types", anchor_types),
        ):

            if values:

                parts.append(
                    f"{label}: "
                    + "; ".join(
                        values
                    )
                    + "."
                )

        if messages:

            parts.append(
                "Representative event messages: "
                + " | ".join(
                    messages
                )
                + "."
            )

    return " ".join(
        parts
    )


def build_incident_context_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic full incident context. "
            "This record describes chronological events before, "
            "at, and after an incident anchor."
        ),
    ]

    fields = (
        ("Incident type", "IncidentType"),
        ("Anchor time", "AnchorTime"),
        ("Collection event count", "CollectionEventCount"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    events = record.get(
        "Events",
        []
    )

    if isinstance(
        events,
        list
    ):

        providers = []
        event_ids = []
        phases = []
        boot_sessions = []
        categories = []
        messages = []

        for event in events:

            if not isinstance(
                event,
                dict
            ):
                continue

            for field, target in (
                ("Provider", providers),
                ("EventID", event_ids),
                ("IncidentPhase", phases),
                ("BootSessionId", boot_sessions),
                ("Category", categories),
            ):

                value_text = clean_text(
                    event.get(
                        field
                    )
                )

                if (
                    value_text
                    and value_text not in target
                ):

                    target.append(
                        value_text
                    )

            message = clean_text(
                event.get(
                    "Message"
                )
            )

            if (
                message
                and message not in messages
                and len(messages) < 5
            ):

                messages.append(
                    message
                )

        for label, values in (
            ("Providers", providers),
            ("Event IDs", event_ids),
            ("Incident phases", phases),
            ("Boot sessions", boot_sessions),
            ("Categories", categories),
        ):

            if values:

                parts.append(
                    f"{label}: "
                    + "; ".join(
                        values
                    )
                    + "."
                )

        if messages:

            parts.append(
                "Representative context messages: "
                + " | ".join(
                    messages
                )
                + "."
            )

    return " ".join(
        parts
    )


def build_incident_identity_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic identity-to-incident correlation. "
            "This record contains security identity sessions that "
            "overlapped an incident time."
        ),
    ]

    fields = (
        ("Incident type", "IncidentType"),
        ("Incident time", "IncidentTime"),
        ("Identity collection status", "IdentityCollectionStatus"),
        ("Collection window start", "CollectionWindowStart"),
        ("Session count", "SessionCount"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    sessions = record.get(
        "Sessions",
        []
    )

    if isinstance(
        sessions,
        list
    ):

        identities = []
        user_names = []
        logon_types = []
        evidence_bases = []

        for session in sessions:

            if not isinstance(
                session,
                dict
            ):
                continue

            for field, target in (
                ("Identity", identities),
                ("UserName", user_names),
                ("LogonType", logon_types),
                ("EvidenceBasis", evidence_bases),
            ):

                value_text = clean_text(
                    session.get(
                        field
                    )
                )

                if (
                    value_text
                    and value_text not in target
                ):

                    target.append(
                        value_text
                    )

        for label, values in (
            ("Incident identities", identities),
            ("User names", user_names),
            ("Logon types", logon_types),
            ("Evidence bases", evidence_bases),
        ):

            if values:

                parts.append(
                    f"{label}: "
                    + "; ".join(
                        values
                    )
                    + "."
                )

    return " ".join(
        parts
    )


def build_windows_sessions_at_incident_search_text(
    record: dict[str, Any],
) -> str:

    parts = [
        (
            "HALON deterministic Windows-session-to-incident "
            "correlation. This record contains reconstructed "
            "Windows sessions that overlapped an incident time."
        ),
    ]

    fields = (
        ("Incident type", "IncidentType"),
        ("Incident time", "IncidentTime"),
        ("Collection window start", "CollectionWindowStart"),
        ("Session evidence coverage", "SessionEvidenceCoverage"),
        ("Session count", "SessionCount"),
    )

    for label, field in fields:

        value = record.get(
            field
        )

        if value not in (
            None,
            "",
        ):

            parts.append(
                f"{label}: {clean_text(value)}."
            )

    sessions = record.get(
        "Sessions",
        []
    )

    if isinstance(
        sessions,
        list
    ):

        users = []
        source_addresses = []
        states = []
        evidence_bases = []

        for session in sessions:

            if not isinstance(
                session,
                dict
            ):
                continue

            for field, target in (
                ("User", users),
                ("SourceAddress", source_addresses),
                ("SessionStateAtCollection", states),
                ("EvidenceBasis", evidence_bases),
            ):

                value_text = clean_text(
                    session.get(
                        field
                    )
                )

                if (
                    value_text
                    and value_text not in target
                ):

                    target.append(
                        value_text
                    )

        for label, values in (
            ("Users at incident", users),
            ("Session source addresses", source_addresses),
            ("Session states", states),
            ("Evidence bases", evidence_bases),
        ):

            if values:

                parts.append(
                    f"{label}: "
                    + "; ".join(
                        values
                    )
                    + "."
                )

    return " ".join(
        parts
    )


SEARCH_TEXT_BUILDERS = {
    "windowsSessions":
        build_windows_session_search_text,

    "processes":
        build_process_search_text,

    "windowsEvents":
        build_windows_event_search_text,

    "identityEvents":
        build_identity_event_search_text,

    "currentSessions":
        build_current_session_search_text,

    "windowsSessionEvents":
        build_windows_session_event_search_text,

    "services":
        build_service_search_text,

    "identitySessions":
        build_identity_session_search_text,

    "system":
        build_system_search_text,

    "disks":
        build_disk_search_text,

    "eventToProcess":
        build_event_to_process_search_text,

    "processToParent":
        build_process_to_parent_search_text,

    "processToLogon":
        build_process_to_logon_search_text,

    "processToWindowsSession":
        build_process_to_windows_session_search_text,

    "evidenceSummary":
        build_evidence_summary_search_text,

    "eventSummary":
        build_event_summary_search_text,

    "processEvidenceCapability":
        build_process_evidence_capability_search_text,

    "timeline":
        build_timeline_search_text,

    "processLineages":
        build_process_lineage_search_text,

    "processExecutionContexts":
        build_process_execution_context_search_text,

    "incidents":
        build_incident_search_text,

    "incidentContexts":
        build_incident_context_search_text,

    "incidentIdentities":
        build_incident_identity_search_text,

    "windowsSessionsAtIncident":
        build_windows_sessions_at_incident_search_text,
}


# ============================================================
# PAYLOAD LOADING
# ============================================================


def load_payload(
    payload_path: Path,
) -> dict[str, Any]:

    with payload_path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:

        payload = json.load(
            file
        )

    if not isinstance(
        payload,
        dict
    ):

        raise ValueError(
            "HALON Evidence Payload must be a JSON object."
        )

    return payload


def get_family_records(
    payload: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:

    evidence = payload.get(
        "evidence",
        {}
    )

    reconstructions = payload.get(
        "reconstructions",
        {}
    )

    relationships = payload.get(
        "relationships",
        {}
    )

    summaries = payload.get(
        "summaries",
        {}
    )

    capabilities = payload.get(
        "capabilities",
        {}
    )

    host = evidence.get(
        "host",
        {}
    )

    sessions = evidence.get(
        "sessions",
        {}
    )

    raw_families = {
        "windowsSessions":
            reconstructions.get(
                "windowsSessions",
                []
            ),

        "processes":
            evidence.get(
                "processes",
                []
            ),

        "windowsEvents":
            evidence.get(
                "windowsEvents",
                []
            ),

        "identityEvents":
            evidence.get(
                "identityEvents",
                []
            ),

        "currentSessions":
            sessions.get(
                "current",
                []
            ),

        "windowsSessionEvents":
            sessions.get(
                "windowsSessionEvents",
                []
            ),

        "services":
            host.get(
                "services",
                []
            ),

        "identitySessions":
            reconstructions.get(
                "identitySessions",
                []
            ),

        "system":
            (
                [host.get("system")]
                if isinstance(
                    host.get("system"),
                    dict
                )
                else []
            ),

        "disks":
            host.get(
                "disks",
                []
            ),

        "eventToProcess":
            relationships.get(
                "eventToProcess",
                []
            ),

        "processToParent":
            relationships.get(
                "processToParent",
                []
            ),

        "processToLogon":
            relationships.get(
                "processToLogon",
                []
            ),

        "processToWindowsSession":
            relationships.get(
                "processToWindowsSession",
                []
            ),

        "evidenceSummary":
            summaries.get(
                "evidence",
                []
            ),

        "eventSummary":
            summaries.get(
                "events",
                []
            ),

        "processEvidenceCapability":
            (
                [capabilities.get("processEvidence")]
                if isinstance(
                    capabilities.get("processEvidence"),
                    dict
                )
                else []
            ),

        "timeline":
            reconstructions.get(
                "timeline",
                []
            ),

        "processLineages":
            reconstructions.get(
                "processLineages",
                []
            ),

        "processExecutionContexts":
            reconstructions.get(
                "processExecutionContexts",
                []
            ),

        "incidents":
            reconstructions.get(
                "incidents",
                []
            ),

        "incidentContexts":
            reconstructions.get(
                "incidentContexts",
                []
            ),

        "incidentIdentities":
            reconstructions.get(
                "incidentIdentities",
                []
            ),

        "windowsSessionsAtIncident":
            reconstructions.get(
                "windowsSessionsAtIncident",
                []
            ),
    }

    families = {}

    for family, records in raw_families.items():

        if not isinstance(
            records,
            list
        ):

            families[
                family
            ] = []

            continue

        families[
            family
        ] = [
            record
            for record in records
            if isinstance(
                record,
                dict
            )
        ]

    return families


# ============================================================
# HALON METADATA / PROVENANCE RECORDS
#
# These records belong in the Knowledge Engine but are not
# searchable machine-evidence families and do not appear in the
# Evidence Family Catalog.
# ============================================================


def get_metadata_records(
    payload: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:

    provenance = payload.get(
        "provenance",
        {}
    )

    agent_diagnostics = payload.get(
        "agentDiagnostics",
        {}
    )

    raw_metadata = {
        "payloadMetadata":
            (
                [payload.get("payloadMetadata")]
                if isinstance(
                    payload.get("payloadMetadata"),
                    dict
                )
                else []
            ),

        "sourceManifest":
            (
                [provenance.get("sourceManifest")]
                if isinstance(
                    provenance.get("sourceManifest"),
                    dict
                )
                else []
            ),

        "artifactIndex":
            provenance.get(
                "artifactIndex",
                []
            ),

        "relationshipSummary":
            (
                [payload.get("relationshipSummary")]
                if isinstance(
                    payload.get("relationshipSummary"),
                    dict
                )
                else []
            ),

        "agentPerformance":
            (
                [agent_diagnostics.get("performance")]
                if isinstance(
                    agent_diagnostics.get("performance"),
                    dict
                )
                else []
            ),
    }

    metadata_records = {}

    for metadata_type, records in raw_metadata.items():

        if not isinstance(
            records,
            list
        ):

            metadata_records[
                metadata_type
            ] = []

            continue

        metadata_records[
            metadata_type
        ] = [
            record
            for record in records
            if isinstance(
                record,
                dict
            )
        ]

    return metadata_records


def build_metadata_rows(
    metadata_type: str,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    if metadata_type not in METADATA_TABLES:

        raise ValueError(
            f"Unsupported HALON metadata type: {metadata_type}"
        )

    rows = []

    for index, record in enumerate(
        records,
        start=1,
    ):

        rows.append(
            {
                "id":
                    f"{metadata_type}:{index}",

                "sourceType":
                    "HALON_METADATA",

                "metadataType":
                    metadata_type,

                "originalRecord":
                    json.dumps(
                        record,
                        ensure_ascii=False,
                    ),
            }
        )

    return rows


# ============================================================
# FAMILY ROW CONSTRUCTION
# ============================================================


def build_family_rows(
    family: str,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    if family not in SEARCH_TEXT_BUILDERS:

        raise ValueError(
            f"Unsupported HALON evidence family: {family}"
        )

    builder = (
        SEARCH_TEXT_BUILDERS[
            family
        ]
    )

    rows = []

    for index, record in enumerate(
        records,
        start=1,
    ):

        rows.append(
            {
                "id":
                    f"{family}:{index}",

                "sourceType":
                    "HALON_EVIDENCE",

                "family":
                    family,

                "searchText":
                    builder(
                        record
                    ),

                "timestamp":
                    get_record_timestamp(
                        record
                    ),

                "identity":
                    get_record_identity(
                        record
                    ),

                "recordId":
                    get_record_id(
                        record
                    ),

                "originalRecord":
                    json.dumps(
                        record,
                        ensure_ascii=False,
                    ),
            }
        )

    return rows


# ============================================================
# HALON KNOWLEDGE ENGINE
# ============================================================


class HalonKnowledgeEngine:

    def __init__(
        self,
        database_path: Path,
        embedding_model_name: str =
            EMBEDDING_MODEL_NAME,
    ) -> None:

        self.database_path = (
            database_path
        )

        self.database_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.db = lancedb.connect(
            str(
                self.database_path
            )
        )

        self.embedding_model = (
            SentenceTransformer(
                embedding_model_name,
                local_files_only=True,
            )
        )

    # ========================================================
    # REBUILD EVIDENCE FAMILY SHELVES
    # ========================================================

    def rebuild_evidence_families(
        self,
        payload_path: Path,
    ) -> dict[str, int]:

        payload = load_payload(
            payload_path
        )

        family_records = (
            get_family_records(
                payload
            )
        )

        counts = {}

        for family, records in family_records.items():

            rows = build_family_rows(
                family=family,
                records=records,
            )

            if not rows:

                counts[
                    family
                ] = 0

                continue

            search_texts = [
                row[
                    "searchText"
                ]
                for row in rows
            ]

            vectors = (
                self.embedding_model
                .encode(
                    search_texts,
                    normalize_embeddings=True,
                    show_progress_bar=True,
                )
            )

            for row, vector in zip(
                rows,
                vectors,
            ):

                row[
                    "vector"
                ] = (
                    vector.tolist()
                )

            self.db.create_table(
                FAMILY_TABLES[
                    family
                ],
                data=rows,
                mode="overwrite",
            )

            counts[
                family
            ] = len(
                rows
            )

        self.rebuild_metadata_tables(
            payload=
                payload,
        )

        self.rebuild_family_catalog()

        return counts

    # ========================================================
    # REBUILD HALON METADATA / PROVENANCE TABLES
    # ========================================================

    def rebuild_metadata_tables(
        self,
        payload: dict[str, Any],
    ) -> dict[str, int]:

        metadata_records = (
            get_metadata_records(
                payload
            )
        )

        counts = {}

        for metadata_type, records in metadata_records.items():

            rows = build_metadata_rows(
                metadata_type=
                    metadata_type,

                records=
                    records,
            )

            if not rows:

                counts[
                    metadata_type
                ] = 0

                continue

            self.db.create_table(
                METADATA_TABLES[
                    metadata_type
                ],
                data=
                    rows,
                mode=
                    "overwrite",
            )

            counts[
                metadata_type
            ] = len(
                rows
            )

        return counts

    # ========================================================
    # REBUILD FAMILY CATALOG
    # ========================================================

    def rebuild_family_catalog(
        self,
    ) -> int:

        rows = [
            {
                "family":
                    family,

                "description":
                    description,
            }
            for family, description
            in FAMILY_CATALOG.items()
        ]

        descriptions = [
            row[
                "description"
            ]
            for row in rows
        ]

        vectors = (
            self.embedding_model
            .encode(
                descriptions,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
        )

        for row, vector in zip(
            rows,
            vectors,
        ):

            row[
                "vector"
            ] = (
                vector.tolist()
            )

        self.db.create_table(
            FAMILY_CATALOG_TABLE,
            data=rows,
            mode="overwrite",
        )

        return len(
            rows
        )

    # ========================================================
    # FIND RELEVANT EVIDENCE FAMILIES
    # ========================================================

    def find_relevant_families(
        self,
        query_vector: list[float],
        limit: int = 2,
    ) -> list[dict[str, Any]]:

        try:

            table = (
                self.db.open_table(
                    FAMILY_CATALOG_TABLE
                )
            )

        except Exception as error:

            raise RuntimeError(
                "HALON Family Catalog does not exist. "
                "Run with --rebuild first."
            ) from error

        results = (
            table
            .search(
                query_vector
            )
            .limit(
                max(
                    1,
                    min(
                        limit,
                        len(
                            FAMILY_CATALOG
                        ),
                    ),
                )
            )
            .to_list()
        )

        return [
            {
                "family":
                    result.get(
                        "family"
                    ),

                "distance":
                    result.get(
                        "_distance"
                    ),

                "description":
                    result.get(
                        "description"
                    ),
            }
            for result in results
        ]

    # ========================================================
    # RETRIEVAL COMPLETENESS
    #
    # Semantic top-N retrieval is excellent for finding relevant
    # evidence, but it must not be mistaken for an exhaustive
    # enumeration.
    #
    # For explicit enumeration questions, HALON can deterministically
    # expand retrieval using literal query terms. The original stored
    # HALON records remain the source of truth.
    # ========================================================

    @staticmethod
    def is_enumeration_query(
        query: str,
    ) -> bool:

        normalized = (
            query
            .strip()
            .lower()
        )

        prefixes = (
            "what ",
            "which ",
            "who ",
            "list ",
            "show ",
            "how many ",
        )

        return (
            normalized.startswith(
                prefixes
            )
            or " activity" in normalized
            or " occurred" in normalized
        )

    @staticmethod
    def extract_enumeration_terms(
        query: str,
    ) -> list[str]:

        tokens = re.findall(
            r"[A-Za-z0-9_.-]+",
            query.lower(),
        )

        stop_words = {
            "a",
            "all",
            "an",
            "and",
            "any",
            "are",
            "at",
            "available",
            "be",
            "been",
            "by",
            "collection",
            "did",
            "during",
            "evidence",
            "event",
            "events",
            "for",
            "from",
            "had",
            "has",
            "have",
            "how",
            "in",
            "into",
            "is",
            "it",
            "list",
            "logged",
            "machine",
            "many",
            "occurred",
            "of",
            "on",
            "process",
            "processes",
            "record",
            "records",
            "session",
            "sessions",
            "show",
            "the",
            "this",
            "to",
            "user",
            "users",
            "was",
            "were",
            "what",
            "which",
            "who",
            "with",
            "activity",
        }

        terms = []

        for token in tokens:

            if len(token) < 3:
                continue

            if token in stop_words:
                continue

            if token not in terms:
                terms.append(
                    token
                )

        return terms

    def get_family_record_count(
        self,
        family: str,
    ) -> int:

        if family not in FAMILY_TABLES:

            raise ValueError(
                f"Unknown HALON evidence family: {family}"
            )

        try:

            table = (
                self.db.open_table(
                    FAMILY_TABLES[
                        family
                    ]
                )
            )

            return int(
                table.count_rows()
            )

        except Exception:

            return 0

    @staticmethod
    def normalize_stored_row(
        result: dict[str, Any],
    ) -> dict[str, Any]:

        return {
            "distance":
                result.get(
                    "_distance"
                ),

            "sourceType":
                result.get(
                    "sourceType"
                ),

            "family":
                result.get(
                    "family"
                ),

            "searchText":
                result.get(
                    "searchText"
                ),

            "metadata": {
                "timestamp":
                    result.get(
                        "timestamp"
                    ),

                "identity":
                    result.get(
                        "identity"
                    ),

                "recordId":
                    result.get(
                        "recordId"
                    ),
            },

            "record":
                json.loads(
                    result[
                        "originalRecord"
                    ]
                ),
        }

    def get_all_family_rows(
        self,
        family: str,
    ) -> list[dict[str, Any]]:

        if family not in FAMILY_TABLES:

            raise ValueError(
                f"Unknown HALON evidence family: {family}"
            )

        try:

            table = (
                self.db.open_table(
                    FAMILY_TABLES[
                        family
                    ]
                )
            )

            stored_rows = (
                table
                .to_arrow()
                .to_pylist()
            )

        except Exception:

            return []

        return [
            self.normalize_stored_row(
                row
            )
            for row in stored_rows
        ]

    @staticmethod
    def process_primary_text(
        record: dict[str, Any],
    ) -> str:

        process_name = first_value(
            record,
            "ProcessName",
            "processName",
            "Name",
            "NewProcessName",
        )

        if process_name is None:

            return ""

        return clean_text(
            process_name
        ).lower()

    def search_family_exact_terms(
        self,
        family: str,
        terms: list[str],
    ) -> list[dict[str, Any]]:

        if not terms:

            return []

        rows = (
            self.get_all_family_rows(
                family
            )
        )

        matches = []

        for row in rows:

            if family == "processes":

                haystack = (
                    self.process_primary_text(
                        row[
                            "record"
                        ]
                    )
                )

            else:

                haystack = str(
                    row.get(
                        "searchText",
                        "",
                    )
                ).lower()

            if all(
                term in haystack
                for term in terms
            ):

                matches.append(
                    row
                )

        return matches

    # ========================================================
    # COMPACT ENUMERATION FOR REASONING
    #
    # HALON may deterministically enumerate hundreds or thousands
    # of matching records. The model does not need every full JSON
    # record in its prompt.
    #
    # The summary below is derived only from the complete matching
    # HALON record set. A bounded number of original records are
    # retained as supporting detail.
    # ========================================================

    @staticmethod
    def _increment_count(
        counts: dict[str, int],
        value: Any,
    ) -> None:

        if value in (
            None,
            "",
        ):

            return

        key = clean_text(
            value
        )

        if not key:

            return

        counts[
            key
        ] = (
            counts.get(
                key,
                0,
            )
            + 1
        )

    @staticmethod
    def _sorted_counts(
        counts: dict[str, int],
    ) -> list[dict[str, Any]]:

        return [
            {
                "value":
                    value,

                "count":
                    count,
            }
            for value, count in sorted(
                counts.items(),
                key=lambda item: (
                    -item[1],
                    item[0].lower(),
                ),
            )
        ]

    def build_process_enumeration_summary(
        self,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:

        process_names = {}
        parent_processes = {}
        identities = {}

        timestamps = []

        command_line_present = 0
        command_line_missing = 0

        for row in rows:

            record = row[
                "record"
            ]

            self._increment_count(
                process_names,
                first_value(
                    record,
                    "ProcessName",
                    "processName",
                    "Name",
                    "NewProcessName",
                ),
            )

            self._increment_count(
                parent_processes,
                first_value(
                    record,
                    "ParentProcessName",
                    "ParentProcess",
                    "CreatorProcessName",
                ),
            )

            self._increment_count(
                identities,
                first_value(
                    record,
                    "SubjectIdentity",
                    "Identity",
                    "User",
                    "UserName",
                    "TargetIdentity",
                ),
            )

            timestamp = (
                row.get(
                    "metadata",
                    {}
                ).get(
                    "timestamp"
                )
                or get_record_timestamp(
                    record
                )
            )

            if timestamp:

                timestamps.append(
                    timestamp
                )

            command_line = first_value(
                record,
                "CommandLine",
                "ProcessCommandLine",
            )

            if command_line in (
                None,
                "",
            ):

                command_line_missing += 1

            else:

                command_line_present += 1

        timestamps = sorted(
            timestamps
        )

        return {
            "matchedRecordCount":
                len(
                    rows
                ),

            "earliestObservedTime":
                (
                    timestamps[0]
                    if timestamps
                    else ""
                ),

            "latestObservedTime":
                (
                    timestamps[-1]
                    if timestamps
                    else ""
                ),

            "processNameCounts":
                self._sorted_counts(
                    process_names
                ),

            "parentProcessCounts":
                self._sorted_counts(
                    parent_processes
                ),

            "identityCounts":
                self._sorted_counts(
                    identities
                ),

            "commandLinePresentCount":
                command_line_present,

            "commandLineMissingCount":
                command_line_missing,
        }

    @staticmethod
    def select_enumeration_detail_rows(
        rows: list[dict[str, Any]],
        detail_limit: int,
    ) -> list[dict[str, Any]]:

        if len(
            rows
        ) <= detail_limit:

            return rows

        ordered = sorted(
            rows,
            key=lambda row: (
                row.get(
                    "metadata",
                    {}
                ).get(
                    "timestamp"
                )
                or ""
            ),
        )

        first_count = (
            detail_limit
            // 2
        )

        last_count = (
            detail_limit
            - first_count
        )

        return (
            ordered[
                :first_count
            ]
            + ordered[
                -last_count:
            ]
        )

    # ========================================================
    # SEARCH ONE FAMILY
    # ========================================================

    def search_family(
        self,
        family: str,
        query_vector: list[float],
        limit: int,
    ) -> list[dict[str, Any]]:

        if family not in FAMILY_TABLES:

            raise ValueError(
                f"Unknown HALON evidence family: {family}"
            )

        table_name = (
            FAMILY_TABLES[
                family
            ]
        )

        try:

            table = (
                self.db.open_table(
                    table_name
                )
            )

        except Exception:

            return []

        results = (
            table
            .search(
                query_vector
            )
            .limit(
                max(
                    1,
                    limit,
                )
            )
            .to_list()
        )

        return [
            self.normalize_stored_row(
                result
            )
            for result in results
        ]

    # ========================================================
    # BALANCED SEARCH ACROSS ALL FAMILIES
    #
    # Every family receives the same query and contributes its
    # own top-N candidates. We deliberately do not collapse these
    # into one global top-N yet.
    # ========================================================

    def search_evidence_families(
        self,
        query: str,
        per_family_limit: int = 5,
    ) -> dict[str, list[dict[str, Any]]]:

        if not isinstance(
            query,
            str
        ) or not query.strip():

            raise ValueError(
                "HALON Knowledge Engine requires "
                "a non-empty search query."
            )

        query_vector = (
            self.embedding_model
            .encode(
                query,
                normalize_embeddings=True,
            )
            .tolist()
        )

        results = {}

        for family in FAMILY_TABLES:

            results[
                family
            ] = (
                self.search_family(
                    family=family,
                    query_vector=
                        query_vector,
                    limit=
                        per_family_limit,
                )
            )

        return results

    # ========================================================
    # FAMILY-CATALOG SEARCH
    #
    # Embed the question once, retrieve the most relevant family
    # catalog cards, then search only those selected shelves.
    # ========================================================

    def search_with_family_catalog(
        self,
        query: str,
        family_limit: int = 2,
        per_family_limit: int = 3,
    ) -> tuple[
        list[dict[str, Any]],
        dict[str, list[dict[str, Any]]],
    ]:

        if not isinstance(
            query,
            str
        ) or not query.strip():

            raise ValueError(
                "HALON Knowledge Engine requires "
                "a non-empty search query."
            )

        query_vector = (
            self.embedding_model
            .encode(
                query,
                normalize_embeddings=True,
            )
            .tolist()
        )

        catalog_results = (
            self.find_relevant_families(
                query_vector=
                    query_vector,

                limit=
                    family_limit,
            )
        )

        family_results = {}

        for catalog_result in catalog_results:

            family = (
                catalog_result[
                    "family"
                ]
            )

            family_results[
                family
            ] = (
                self.search_family(
                    family=
                        family,

                    query_vector=
                        query_vector,

                    limit=
                        per_family_limit,
                )
            )

        return (
            catalog_results,
            family_results,
        )

    # ========================================================
    # QUERY HALON EVIDENCE FOR REASONING
    #
    # Public Knowledge -> Reasoning contract.
    #
    # Semantic retrieval decides where to look.
    # Original HALON records remain the factual source.
    # ========================================================

    def query_evidence(
        self,
        query: str,
        family_limit: int = 2,
        per_family_limit: int = 3,
        enumeration_detail_limit: int = 8,
        full_family_limit: int = 50,
    ) -> dict[str, Any]:

        (
            catalog_results,
            family_results,
        ) = self.search_with_family_catalog(
            query=query,
            family_limit=family_limit,
            per_family_limit=per_family_limit,
        )

        enumeration_requested = (
            self.is_enumeration_query(
                query
            )
        )

        enumeration_terms = (
            self.extract_enumeration_terms(
                query
            )
            if enumeration_requested
            else []
        )

        coverage = {}
        enumeration_summaries = {}

        for catalog_result in catalog_results:

            family = (
                catalog_result[
                    "family"
                ]
            )

            total_count = (
                self.get_family_record_count(
                    family
                )
            )

            records = family_results.get(
                family,
                [],
            )

            mode = "semanticTopN"

            complete = (
                len(
                    records
                )
                >= total_count
                and total_count > 0
            )

            matched_count = None
            detail_complete = complete

            if enumeration_requested:

                if enumeration_terms:

                    exact_records = (
                        self.search_family_exact_terms(
                            family=
                                family,

                            terms=
                                enumeration_terms,
                        )
                    )

                    matched_count = len(
                        exact_records
                    )

                    mode = (
                        "exactTermEnumeration"
                    )

                    complete = True

                    if (
                        family == "processes"
                        and exact_records
                    ):

                        enumeration_summaries[
                            family
                        ] = (
                            self.build_process_enumeration_summary(
                                exact_records
                            )
                        )

                    records = (
                        self.select_enumeration_detail_rows(
                            rows=
                                exact_records,

                            detail_limit=
                                enumeration_detail_limit,
                        )
                    )

                    family_results[
                        family
                    ] = records

                    detail_complete = (
                        len(
                            records
                        )
                        == matched_count
                    )

                elif (
                    total_count
                    <= full_family_limit
                ):

                    records = (
                        self.get_all_family_rows(
                            family
                        )
                    )

                    family_results[
                        family
                    ] = records

                    matched_count = len(
                        records
                    )

                    mode = (
                        "fullFamilyEnumeration"
                    )

                    complete = True
                    detail_complete = True

            coverage[
                family
            ] = {
                "mode":
                    mode,

                "availableRecordCount":
                    total_count,

                "returnedDetailCount":
                    len(
                        records
                    ),

                "matchedRecordCount":
                    matched_count,

                "complete":
                    complete,

                "detailComplete":
                    detail_complete,
            }

        record_count = sum(
            len(records)
            for records in family_results.values()
        )

        if enumeration_requested:

            complete_for_question = all(
                item[
                    "complete"
                ]
                for item in coverage.values()
            )

        else:

            complete_for_question = None

        return {
            "sourceType":
                "HALON_EVIDENCE",

            "query":
                query,

            "retrieval": {
                "familyLimit":
                    family_limit,

                "perFamilyLimit":
                    per_family_limit,

                "recordCount":
                    record_count,

                "selectedFamilies":
                    catalog_results,

                "enumerationRequested":
                    enumeration_requested,

                "enumerationTerms":
                    enumeration_terms,

                "completeForQuestion":
                    complete_for_question,

                "familyCoverage":
                    coverage,

                "enumerationSummaries":
                    enumeration_summaries,
            },

            "families":
                family_results,
        }


# ============================================================
# CLI
# ============================================================


def main() -> None:

    script_path = Path(
        __file__
    ).resolve()

    root = (
        script_path
        .parents[
            2
        ]
    )

    default_payload = (
        root
        / "output"
        / "WADESYSTEM_20260829_140700"
        / "evidence-payload-v1.json"
    )

    default_database = (
        root
        / "data"
        / "knowledge"
    )

    parser = argparse.ArgumentParser(
        description=(
            "HALON Knowledge Engine "
            "family-catalog evidence retrieval."
        )
    )

    parser.add_argument(
        "--payload",
        type=Path,
        default=default_payload,
        help=(
            "Path to evidence-payload-v1.json."
        ),
    )

    parser.add_argument(
        "--database",
        type=Path,
        default=default_database,
        help=(
            "Local LanceDB database directory."
        ),
    )

    parser.add_argument(
        "--rebuild",
        action="store_true",
        help=(
            "Rebuild HALON evidence-family shelves "
            "and the Family Catalog from the current payload."
        ),
    )

    parser.add_argument(
        "--rebuild-catalog",
        action="store_true",
        help=(
            "Rebuild only the Family Catalog. "
            "Existing evidence-family shelves are unchanged."
        ),
    )

    parser.add_argument(
        "--query",
        default=(
            "Who used this computer?"
        ),
        help=(
            "Natural-language evidence search query."
        ),
    )

    parser.add_argument(
        "--per-family-limit",
        type=int,
        default=3,
        help=(
            "Maximum candidates returned from each "
            "evidence family."
        ),
    )

    parser.add_argument(
        "--family-limit",
        type=int,
        default=2,
        help=(
            "Maximum number of evidence families selected "
            "by the semantic Family Catalog."
        ),
    )

    parser.add_argument(
        "--family",
        choices=[
            "catalog",
            "all",
            *FAMILY_TABLES.keys(),
        ],
        default="catalog",
        help=(
            "Use the Family Catalog, search all evidence "
            "families, or search one specific family."
        ),
    )

    args = parser.parse_args()

    engine = (
        HalonKnowledgeEngine(
            database_path=
                args.database,
        )
    )

    if args.rebuild:

        counts = (
            engine.rebuild_evidence_families(
                payload_path=
                    args.payload,
            )
        )

        print()
        print(
            "HALON Evidence family shelves rebuilt."
        )

        print()

        for family, count in counts.items():

            print(
                f"{family}: {count}"
            )

    elif args.rebuild_catalog:

        catalog_count = (
            engine.rebuild_family_catalog()
        )

        print()
        print(
            "HALON Family Catalog rebuilt."
        )

        print(
            f"familyCatalog: {catalog_count}"
        )

    catalog_results = []

    if args.family == "catalog":

        (
            catalog_results,
            family_results,
        ) = (
            engine.search_with_family_catalog(
                query=
                    args.query,

                family_limit=
                    args.family_limit,

                per_family_limit=
                    args.per_family_limit,
            )
        )

    elif args.family == "all":

        family_results = (
            engine.search_evidence_families(
                query=
                    args.query,

                per_family_limit=
                    args.per_family_limit,
            )
        )

    else:

        query_vector = (
            engine.embedding_model
            .encode(
                args.query,
                normalize_embeddings=True,
            )
            .tolist()
        )

        family_results = {
            args.family:
                engine.search_family(
                    family=
                        args.family,

                    query_vector=
                        query_vector,

                    limit=
                        args.per_family_limit,
                )
        }

    print()
    print(
        f"Query: {args.query}"
    )

    print()

    if catalog_results:

        print(
            "============================================================"
        )

        print(
            "FAMILY CATALOG"
        )

        print(
            f"SELECTED FAMILIES: {len(catalog_results)}"
        )

        print(
            "============================================================"
        )

        for index, result in enumerate(
            catalog_results,
            start=1,
        ):

            print()

            print(
                f"{index}. {result['family']}"
            )

            print(
                f"Distance: {result['distance']}"
            )

            print(
                f"Description: {result['description']}"
            )

        print()

    for family, results in family_results.items():

        print(
            "============================================================"
        )

        print(
            f"FAMILY: {family}"
        )

        print(
            f"RESULTS: {len(results)}"
        )

        print(
            "============================================================"
        )

        for index, result in enumerate(
            results,
            start=1,
        ):

            print()
            print(
                f"Result {index}"
            )

            print(
                f"Distance: {result['distance']}"
            )

            print(
                "Metadata:"
            )

            print(
                json.dumps(
                    result[
                        "metadata"
                    ],
                    indent=2,
                    ensure_ascii=False,
                )
            )

            print(
                "Search Text:"
            )

            print(
                result[
                    "searchText"
                ]
            )

            print(
                "Original HALON Record:"
            )

            print(
                json.dumps(
                    result[
                        "record"
                    ],
                    indent=2,
                    ensure_ascii=False,
                )
            )

        print()


if __name__ == "__main__":
    main()
