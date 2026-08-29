import json
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any


# ============================================================
# HALON EVIDENCE ADAPTER
#
# Canonical HALON evidence optimizes for fidelity.
# Reasoning-ready HALON evidence optimizes for semantic clarity.
#
# This adapter:
#   - does NOT query Windows
#   - does NOT add technical interpretation
#   - does NOT infer causation
#   - does NOT modify canonical evidence
#
# It restructures existing evidence into an explicit,
# reasoning-friendly representation.
# ============================================================


def load_payload(path: Path) -> dict[str, Any]:

    with path.open(
        "r",
        encoding="utf-8-sig"
    ) as file:

        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(
            "HALON Evidence Payload must be a JSON object."
        )

    return payload


# ============================================================
# BASIC HELPERS
# ============================================================


def windows_basename(
    value: Any
) -> str | None:

    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    return PureWindowsPath(text).name


def normalize_key(
    value: Any
) -> str:

    return str(value).strip().lower()


def parse_halon_time(
    value: Any
) -> datetime:

    if value is None:
        return datetime.min

    text = str(value).strip()

    formats = (
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    )

    for format_string in formats:

        try:
            return datetime.strptime(
                text,
                format_string
            )

        except ValueError:
            continue

    return datetime.min


def get_case_insensitive(
    source: dict[str, Any],
    *names: str
) -> Any:

    if not isinstance(source, dict):
        return None

    key_map = {
        str(key).lower(): key
        for key in source.keys()
    }

    for name in names:

        matching_key = key_map.get(
            name.lower()
        )

        if matching_key is not None:

            value = source.get(
                matching_key
            )

            if value not in (
                None,
                ""
            ):
                return value

    return None


def get_structured_event_data(
    event: dict[str, Any] | None
) -> dict[str, Any]:

    if not isinstance(event, dict):
        return {}

    data = (
        event.get("StructuredEventData")
        or event.get("structuredEventData")
    )

    if isinstance(data, dict):
        return data

    return {}


# ============================================================
# EVIDENCE BASIS DEFINITIONS
# ============================================================


EVIDENCE_BASIS = {

    "ProcessIdAndProcessName": {

        "meaning": (
            "HALON matched the process referenced by the "
            "Windows event to a historical process creation "
            "record using compatible process ID, process name, "
            "and chronology."
        ),

        "doesNotEstablish": (
            "That the matched process caused the event, "
            "or that a human intentionally caused the event."
        ),
    },

    "ParentProcessIdAndName": {

        "meaning": (
            "HALON matched the child process to an earlier "
            "historical process creation record using the "
            "recorded parent process ID, compatible process "
            "name, and chronology."
        ),

        "doesNotEstablish": (
            "That a human directly launched the child process "
            "or that the parent caused a later failure."
        ),
    },

    "SecurityLogonIdMatch": {

        "meaning": (
            "HALON matched the process security context to "
            "a Windows Security logon record using the Logon "
            "ID and compatible chronology."
        ),

        "doesNotEstablish": (
            "That the associated human account personally "
            "initiated the process."
        ),
    },

    "ExactSubjectIdentityAndSessionWindow": {

        "meaning": (
            "The process subject identity exactly matched "
            "the Windows session user and the process occurred "
            "inside the observed session interval."
        ),

        "doesNotEstablish": (
            "That the session user manually launched, caused, "
            "or intentionally initiated the process activity."
        ),
    },
}

INTERPRETATION_BOUNDARIES = [

    {
        "topic":
            "HumanInitiation",

        "statement": (
            "Process security context, Windows logon "
            "correlation, Windows session membership, and "
            "process ancestry do not independently establish "
            "that a human manually initiated the process."
        ),
    },

    {
        "topic":
            "Causation",

        "statement": (
            "Event-to-process correlation and process ancestry "
            "establish observed relationships. They do not "
            "independently establish the cause of a failure."
        ),
    },

    {
        "topic":
            "IntentAndResponsibility",

        "statement": (
            "Identity, session, and process relationships do "
            "not independently establish human intent or "
            "responsibility for observed activity."
        ),
    },

    {
        "topic":
            "LineageTraversal",

        "statement": (
            "A lineage traversal termination describes where "
            "HALON could no longer continue historical ancestry "
            "reconstruction. It does not mean the target process "
            "had no parent and does not explain why the target "
            "process later failed."
        ),
    },
]

def describe_evidence_basis(
    basis: Any
) -> dict[str, Any]:

    name = (
        str(basis)
        if basis is not None
        else None
    )

    definition = (
        EVIDENCE_BASIS.get(
            name,
            {}
        )
    )

    return {

        "name":
            name,

        "meaning":
            definition.get("meaning"),
    }

# ============================================================
# PAYLOAD LOOKUPS
# ============================================================


def get_event_process_relationships(
    payload: dict[str, Any]
) -> list[dict[str, Any]]:

    value = (
        payload
        .get("relationships", {})
        .get("eventToProcess", [])
    )

    return (
        value
        if isinstance(value, list)
        else []
    )


def get_processes(
    payload: dict[str, Any]
) -> list[dict[str, Any]]:

    value = (
        payload
        .get("evidence", {})
        .get("processes", [])
    )

    return (
        value
        if isinstance(value, list)
        else []
    )


def get_windows_events(
    payload: dict[str, Any]
) -> list[dict[str, Any]]:

    value = (
        payload
        .get("evidence", {})
        .get("windowsEvents", [])
    )

    return (
        value
        if isinstance(value, list)
        else []
    )


def get_relationship_collection(
    payload: dict[str, Any],
    name: str
) -> list[dict[str, Any]]:

    value = (
        payload
        .get("relationships", {})
        .get(name, [])
    )

    return (
        value
        if isinstance(value, list)
        else []
    )


def get_process_lineages(
    payload: dict[str, Any]
) -> list[dict[str, Any]]:

    value = (
        payload
        .get("reconstructions", {})
        .get("processLineages", [])
    )

    return (
        value
        if isinstance(value, list)
        else []
    )


# ============================================================
# RECORD LOOKUPS
# ============================================================


def find_latest_event_process_relationship(
    payload: dict[str, Any],
    process_name: str
) -> dict[str, Any] | None:

    target = process_name.lower()

    matches = [

        relationship

        for relationship in
        get_event_process_relationships(
            payload
        )

        if target in str(
            relationship.get(
                "referencedProcessName",
                ""
            )
        ).lower()
    ]

    if not matches:
        return None

    matches.sort(
        key=lambda item:
            parse_halon_time(
                item.get("eventTime")
            ),
        reverse=True,
    )

    return matches[0]


def find_process(
    payload: dict[str, Any],
    process_record_id: Any
) -> dict[str, Any] | None:

    target = normalize_key(
        process_record_id
    )

    for process in get_processes(
        payload
    ):

        if normalize_key(
            process.get(
                "SecurityRecordId"
            )
        ) == target:

            return process

    return None


def find_event(
    payload: dict[str, Any],
    event_record_id: Any
) -> dict[str, Any] | None:

    target = normalize_key(
        event_record_id
    )

    for event in get_windows_events(
        payload
    ):

        if normalize_key(
            event.get("RecordId")
        ) == target:

            return event

    return None


def find_process_relationship(
    payload: dict[str, Any],
    collection_name: str,
    process_record_id: Any
) -> dict[str, Any] | None:

    target = normalize_key(
        process_record_id
    )

    for relationship in (
        get_relationship_collection(
            payload,
            collection_name
        )
    ):

        if (
            collection_name
            == "processToParent"
        ):

            candidate = (
                relationship.get(
                    "childProcessSecurityRecordId"
                )
            )

        else:

            candidate = (
                relationship.get(
                    "processSecurityRecordId"
                )
            )

        if normalize_key(
            candidate
        ) == target:

            return relationship

    return None


def find_process_session_relationships(
    payload: dict[str, Any],
    process_record_id: Any
) -> list[dict[str, Any]]:

    target = normalize_key(
        process_record_id
    )

    matches = []

    for relationship in (
        get_relationship_collection(
            payload,
            "processToWindowsSession"
        )
    ):

        if normalize_key(
            relationship.get(
                "processSecurityRecordId"
            )
        ) == target:

            matches.append(
                relationship
            )

    return matches


def find_process_lineage(
    payload: dict[str, Any],
    process_record_id: Any
) -> dict[str, Any] | None:

    target = normalize_key(
        process_record_id
    )

    for lineage in get_process_lineages(
        payload
    ):

        if normalize_key(
            lineage.get(
                "ProcessSecurityRecordId"
            )
        ) == target:

            return lineage

    return None


# ============================================================
# EVENT ADAPTER
# ============================================================


def build_event_failure_details(
    event: dict[str, Any] | None
) -> dict[str, Any]:

    structured = (
        get_structured_event_data(
            event
        )
    )

    faulting_module = (
        get_case_insensitive(
            structured,
            "ModuleName",
            "FaultingModuleName",
            "FaultingModule"
        )
    )

    module_path = (
        get_case_insensitive(
            structured,
            "ModulePath",
            "FaultingModulePath"
        )
    )

    exception_code = (
        get_case_insensitive(
            structured,
            "ExceptionCode"
        )
    )

    fault_offset = (
        get_case_insensitive(
            structured,
            "FaultingOffset",
            "FaultOffset"
        )
    )

    return {

    "faultingModule": {

        "observedValue":
            faulting_module,

        "modulePath":
            module_path,

        "interpretationStatus":
            (
                "AuthoritativeReferenceRequired"
                if faulting_module is not None
                else "NotObserved"
            ),
    },

    "exceptionCode": {

        "observedValue":
            exception_code,

        "interpretationStatus":
            (
                "AuthoritativeReferenceRequired"
                if exception_code is not None
                else "NotObserved"
            ),
    },

    "faultOffset": {

        "observedValue":
            fault_offset,

        "semanticType":
            "moduleOffset",

        "interpretationStatus":
            (
                "AuthoritativeReferenceRequired"
                if fault_offset is not None
                else "NotObserved"
            ),
    },
}


# ============================================================
# PROCESS LINEAGE ADAPTER
# ============================================================


def build_reasoning_lineage(
    lineage: dict[str, Any] | None
) -> dict[str, Any] | None:

    if not isinstance(
        lineage,
        dict
    ):
        return None

    raw_nodes = lineage.get(
        "Lineage",
        []
    )

    if not isinstance(
        raw_nodes,
        list
    ):
        raw_nodes = []

    nodes = []

    for node in raw_nodes:

        if not isinstance(
            node,
            dict
        ):
            continue

        nodes.append(
            {
                "depth":
                    node.get("Depth"),

                "processTime":
                    node.get("ProcessTime"),

                "processSecurityRecordId":
                    node.get(
                        "SecurityRecordId"
                    ),

                "processId":
                    node.get("ProcessId"),

                "processName":
                    node.get("ProcessName"),

                "processFileName":
                    windows_basename(
                        node.get(
                            "ProcessName"
                        )
                    ),

                "subjectIdentity":
                    node.get(
                        "SubjectIdentity"
                    ),
            }
        )

    terminal_node = (
        nodes[-1]
        if nodes
        else None
    )

    termination_reason = (
        lineage.get(
            "TerminationReason"
        )
    )

    termination_meaning = None

    if (
        termination_reason
        == "NoHistoricalParentProcessMatch"
    ):

        termination_meaning = (
            "HALON successfully reconstructed ancestry "
            "through the listed process nodes, but could "
            "not continue beyond the oldest reconstructed "
            "process using the historical evidence available "
            "inside the collection window."
        )

    elif (
        termination_reason
        == "ParentRecordNotAvailable"
    ):

        termination_meaning = (
            "HALON had a previously established parent "
            "reference but the corresponding parent record "
            "was not available to continue the lineage."
        )

    elif (
        termination_reason
        == "MaxDepthReached"
    ):

        termination_meaning = (
            "HALON stopped lineage traversal because the "
            "configured maximum ancestry depth was reached."
        )

    elif (
        termination_reason
        == "CycleDetected"
    ):

        termination_meaning = (
            "HALON stopped lineage traversal after detecting "
            "a repeated historical process record."
        )

    return {

    "targetProcess": {

        "processSecurityRecordId":
            (
                nodes[0].get(
                    "processSecurityRecordId"
                )
                if nodes
                else None
            ),

        "processName":
            (
                nodes[0].get(
                    "processName"
                )
                if nodes
                else None
            ),

        "processFileName":
            (
                nodes[0].get(
                    "processFileName"
                )
                if nodes
                else None
            ),
    },

    "orderedAncestry": [

        {
            "depth":
                node.get("depth"),

            "processSecurityRecordId":
                node.get(
                    "processSecurityRecordId"
                ),

            "processId":
                node.get(
                    "processId"
                ),

            "processName":
                node.get(
                    "processName"
                ),

            "processFileName":
                node.get(
                    "processFileName"
                ),

            "processTime":
                node.get(
                    "processTime"
                ),
        }

        for node in nodes[1:]
    ],

    "traversal": {

        "ancestorCount":
            max(
                len(nodes) - 1,
                0
            ),

        "terminationReason":
            termination_reason,

        "terminatedAtDepth":
            (
                terminal_node.get(
                    "depth"
                )
                if terminal_node
                else None
            ),

        "terminatedAtProcessSecurityRecordId":
            (
                terminal_node.get(
                    "processSecurityRecordId"
                )
                if terminal_node
                else None
            ),

        "meaning":
            termination_meaning,
    },
}



# ============================================================
# CRASH WORKING SET
# ============================================================


def build_crash_working_set(
    payload: dict[str, Any],
    target_process_name: str
) -> dict[str, Any]:

    event_process = (
        find_latest_event_process_relationship(
            payload,
            target_process_name
        )
    )

    if event_process is None:

        raise RuntimeError(
            f"No event/process relationship found for "
            f"{target_process_name}."
        )

    process_record_id = (
        event_process.get(
            "processSecurityRecordId"
        )
    )

    event = find_event(
        payload,
        event_process.get(
            "eventRecordId"
        )
    )

    process = find_process(
        payload,
        process_record_id
    )

    parent = (
        find_process_relationship(
            payload,
            "processToParent",
            process_record_id
        )
    )

    logon = (
        find_process_relationship(
            payload,
            "processToLogon",
            process_record_id
        )
    )

    sessions = (
        find_process_session_relationships(
            payload,
            process_record_id
        )
    )

    lineage = (
        build_reasoning_lineage(
            find_process_lineage(
                payload,
                process_record_id
            )
        )
    )

    # --------------------------------------------------------
    # TIMELINE
    # --------------------------------------------------------

    timeline = []

    if process is not None:

        timeline.append(
            {
                "time":
                    process.get(
                        "TimeCreated"
                    ),

                "type":
                    "ProcessCreation",

                "description":
                    "Windows recorded creation of the "
                    "target process.",

                "processSecurityRecordId":
                    process.get(
                        "SecurityRecordId"
                    ),

                "processId":
                    process.get(
                        "ProcessIdDecimal"
                    ),

                "processName":
                    process.get(
                        "ProcessName"
                    ),

                "processSecurityContext": {

                "identity":
                    process.get(
                        "SubjectIdentity"
                    ),

                "meaning": (
                    "Windows recorded the process creation "
                    "under this security context."
                    ),
                },
            }
        )

    timeline.append(
        {
            "time":
                event_process.get(
                    "eventTime"
                ),

            "type":
                "WindowsApplicationError",

            "description":
                "Windows recorded an Application Error "
                "event referencing the target process.",

            "eventRecordId":
                event_process.get(
                    "eventRecordId"
                ),

            "eventProvider":
                event_process.get(
                    "eventProvider"
                ),

            "eventId":
                event_process.get(
                    "eventId"
                ),

            "elapsedFromProcessCreation": {

                "value":
                    event_process.get(
                        "processAgeAtEventSeconds"
                    ),

                "unit":
                    "seconds",

                "meaning": (
                    "Elapsed time between the matched "
                    "historical process creation record "
                    "and occurrence of this event."
                ),
            },
        }
    )

    # --------------------------------------------------------
    # EVENT -> PROCESS PROOF
    # --------------------------------------------------------

    event_process_proof = {

        "source": {

            "type":
                "WindowsEvent",

            "recordId":
                event_process.get(
                    "eventRecordId"
                ),

            "eventId":
                event_process.get(
                    "eventId"
                ),

            "provider":
                event_process.get(
                    "eventProvider"
                ),
        },

        "relationship":
            "ReferencesHistoricalProcess",

        "target": {

            "type":
                "HistoricalProcess",

            "processSecurityRecordId":
                process_record_id,

            "processName":
                (
                    process.get(
                        "ProcessName"
                    )
                    if process
                    else None
                ),
        },

        "meaning": (
            "The Windows event referenced the matched "
            "historical process."
        ),

        "evidenceBasis":
            describe_evidence_basis(
                event_process.get(
                    "evidenceBasis"
                )
            ),
    }
    # --------------------------------------------------------
    # DIRECT PARENT PROOF
    # --------------------------------------------------------

    parent_proof = None

    if parent is not None:

        parent_proof = {

            "relationship":
                "ChildOf",

            "childProcessSecurityRecordId":
                parent.get(
                    "childProcessSecurityRecordId"
                ),

            "childProcessName":
                parent.get(
                    "childProcessName"
                ),

            "parentProcessSecurityRecordId":
                parent.get(
                    "parentProcessSecurityRecordId"
                ),

            "parentProcessName":
                parent.get(
                    "parentProcessName"
                ),

            "evidenceBasis":
                describe_evidence_basis(
                    parent.get(
                        "evidenceBasis"
                    )
                ),
        }

    # --------------------------------------------------------
    # SECURITY CONTEXT
    # --------------------------------------------------------

    security_context = None

    if logon is not None:

        security_context = {

            "observedProcessIdentity":
                (
                    process.get(
                        "SubjectIdentity"
                    )
                    if process
                    else None
                ),

            "correlatedSecurityLogon": {

                "identity":
                    logon.get(
                        "logonIdentity"
                    ),

                "userSid":
                    logon.get(
                        "logonUserSid"
                    ),

                "logonType":
                    logon.get(
                        "logonType"
                    ),

                "logonTime":
                    logon.get(
                        "logonTime"
                    ),

                "securityRecordId":
                    logon.get(
                        "logonSecurityRecordId"
                    ),
            },

            "evidenceBasis":
                describe_evidence_basis(
                    logon.get(
                        "evidenceBasis"
                    )
                ),
        }

    # --------------------------------------------------------
    # WINDOWS SESSIONS
    # --------------------------------------------------------

    session_contexts = []

    for session in sessions:

        session_contexts.append(
            {
                "sessionId":
                    session.get(
                        "sessionId"
                    ),

                "user":
                    session.get(
                        "sessionUser"
                    ),

                "sourceAddress":
                    session.get(
                        "sourceAddress"
                    ),

                "sessionStart":
                    session.get(
                        "sessionStart"
                    ),

                "sessionEnd":
                    session.get(
                        "sessionEnd"
                    ),

                "sessionLogonRecordId":
                    session.get(
                        "sessionLogonRecordId"
                    ),

                "evidenceBasis":
                    describe_evidence_basis(
                        session.get(
                            "evidenceBasis"
                        )
                    ),
            }
        )

    # --------------------------------------------------------
    # TECHNICAL OBSERVATIONS
    # --------------------------------------------------------

    failure_details = (
        build_event_failure_details(
            event
        )
    )

    technical_observations = [

    {
        "name":
            "WindowsEventId",

        "observedValue":
            event_process.get(
                "eventId"
            ),

        "provider":
            event_process.get(
                "eventProvider"
            ),

        "interpretationStatus":
            "AuthoritativeReferenceRequired",
    },

    {
        "name":
            "ExceptionCode",

        **failure_details[
            "exceptionCode"
        ],
    },

    {
        "name":
            "FaultingModule",

        **failure_details[
            "faultingModule"
        ],
    },

    {
        "name":
            "FaultOffset",

        **failure_details[
            "faultOffset"
        ],
    },
]

    # Remove completely empty optional observations.
    technical_observations = [

        observation

        for observation in
        technical_observations

        if observation.get(
            "observedValue"
        ) is not None
    ]

    # --------------------------------------------------------
    # FINAL REASONING-READY EVIDENCE
    # --------------------------------------------------------

    return {
        "interpretationBoundaries":
            INTERPRETATION_BOUNDARIES,

        "questionTarget": {

            "processName":
                target_process_name,

            "processSecurityRecordId":
                process_record_id,
        },

        "timeline":
            timeline,

        "targetProcess": {

            "processSecurityRecordId":
                (
                    process.get(
                        "SecurityRecordId"
                    )
                    if process
                    else None
                ),

            "processId":
                (
                    process.get(
                        "ProcessIdDecimal"
                    )
                    if process
                    else None
                ),

            "processName":
                (
                    process.get(
                        "ProcessName"
                    )
                    if process
                    else None
                ),

            "processFileName":
                (
                    windows_basename(
                        process.get(
                            "ProcessName"
                        )
                    )
                    if process
                    else None
                ),

            "created":
                (
                    process.get(
                        "TimeCreated"
                    )
                    if process
                    else None
                ),

            "processSecurityContext": {

                "identity":
                    process.get(
                        "SubjectIdentity"
                    ),
            },

            "subjectLogonId":
                (
                    process.get(
                        "SubjectLogonId"
                    )
                    if process
                    else None
                ),
        },

        "evidenceRelationships": {

            "eventToProcess":
                event_process_proof,

            "directParent":
                parent_proof,

            "securityContext":
                security_context,

            "windowsSessions":
                session_contexts,
        },

        "processLineageSummary": {

    "reconstructedAncestorCount":
        (
            lineage
            .get("traversal", {})
            .get("ancestorCount")
            if lineage
            else 0
        ),

    "oldestReconstructedAncestor":
        (
            {
                "processSecurityRecordId":
                    lineage
                    .get("traversal", {})
                    .get(
                        "terminatedAtProcessSecurityRecordId"
                    ),

                "depth":
                    lineage
                    .get("traversal", {})
                    .get(
                        "terminatedAtDepth"
                    ),
            }
            if lineage
            else None
        ),

    "traversalTerminationReason":
        (
            lineage
            .get("traversal", {})
            .get("terminationReason")
            if lineage
            else None
        ),

    "fullLineageAvailable":
        lineage is not None,
},

"technicalObservations":
    technical_observations,

        "canonicalEvidenceReferences": [

            {
                "artifact":
                    "events.json",

                "recordId":
                    event_process.get(
                        "eventRecordId"
                    ),
            },

            {
                "artifact":
                    "process-events.json",

                "securityRecordId":
                    process_record_id,
            },

            {
                "artifact":
                    "event-process-correlations.json",

                "eventRecordId":
                    event_process.get(
                        "eventRecordId"
                    ),

                "processSecurityRecordId":
                    process_record_id,
            },
        ],
    }