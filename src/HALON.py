import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PAYLOAD_SCHEMA_VERSION = "1.0"
PAYLOAD_BUILDER_VERSION = "0.1.0"


# ============================================================
# JSON / ARTIFACT LOADING
# ============================================================

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def get_record_count(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)

    if isinstance(value, dict):
        return 1

    return None


def load_canonical_artifacts(
    run_directory: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:

    artifacts: dict[str, Any] = {}
    artifact_index: list[dict[str, Any]] = []

    json_files = sorted(
        path
        for path in run_directory.glob("*.json")
        if not path.name.startswith("evidence-payload")
    )

    for path in json_files:

        try:
            content = load_json(path)

        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid JSON in canonical artifact "
                f"{path.name}: {error}"
            ) from error

        artifact_name = path.stem

        artifacts[artifact_name] = content

        if isinstance(content, list):
            artifact_type = "collection"

        elif isinstance(content, dict):
            artifact_type = "object"

        else:
            artifact_type = "scalar"

        artifact_index.append(
            {
                "artifact": path.name,
                "artifactType": artifact_type,
                "recordCount": get_record_count(content),
            }
        )

    return artifacts, artifact_index


# ============================================================
# CANONICAL ARTIFACT ACCESS
# ============================================================

def get_collection(
    artifacts: dict[str, Any],
    name: str
) -> list[Any]:

    value = artifacts.get(name)

    if isinstance(value, list):
        return value

    return []


def get_object(
    artifacts: dict[str, Any],
    name: str
) -> dict[str, Any] | None:

    value = artifacts.get(name)

    if isinstance(value, dict):
        return value

    return None


# ============================================================
# RELATIONSHIP INDEX BUILDERS
# ============================================================

def build_event_process_relationships(
    artifacts: dict[str, Any]
) -> list[dict[str, Any]]:

    relationships: list[dict[str, Any]] = []

    for correlation in get_collection(
        artifacts,
        "event-process-correlations"
    ):

        process_record_id = correlation.get(
            "HistoricalProcessSecurityRecordId"
        )

        if process_record_id is None:
            continue

        relationships.append(
            {
                "relationship": "ReferencesHistoricalProcess",

                "eventRecordId":
                    correlation.get("EventRecordId"),

                "eventTime":
                    correlation.get("EventTime"),

                "eventProvider":
                    correlation.get("EventProvider"),

                "eventId":
                    correlation.get("EventID"),

                "referencedProcessId":
                    correlation.get("ReferencedProcessId"),

                "referencedProcessName":
                    correlation.get("ReferencedProcessName"),

                "processSecurityRecordId":
                    process_record_id,

                "historicalProcessName":
                    correlation.get("HistoricalProcessName"),

                "processAgeAtEventSeconds":
                    correlation.get("ProcessAgeAtEventSeconds"),

                "evidenceBasis":
                    correlation.get("MatchBasis"),
            }
        )

    return relationships


def build_process_parent_relationships(
    artifacts: dict[str, Any]
) -> list[dict[str, Any]]:

    relationships: list[dict[str, Any]] = []

    for process_lineage in get_collection(
        artifacts,
        "process-lineage"
    ):

        lineage = process_lineage.get("Lineage")

        if not isinstance(lineage, list):
            continue

        if len(lineage) < 2:
            continue

        child = lineage[0]
        parent = lineage[1]

        child_record_id = child.get(
            "SecurityRecordId"
        )

        parent_record_id = parent.get(
            "SecurityRecordId"
        )

        if (
            child_record_id is None
            or parent_record_id is None
        ):
            continue

        relationships.append(
            {
                "relationship": "ChildOf",

                "childProcessSecurityRecordId":
                    child_record_id,

                "childProcessId":
                    child.get("ProcessId"),

                "childProcessName":
                    child.get("ProcessName"),

                "parentProcessSecurityRecordId":
                    parent_record_id,

                "parentProcessId":
                    parent.get("ProcessId"),

                "parentProcessName":
                    parent.get("ProcessName"),

                "evidenceBasis":
                    child.get("EvidenceBasisToParent"),
            }
        )

    return relationships


def build_process_logon_relationships(
    artifacts: dict[str, Any]
) -> list[dict[str, Any]]:

    relationships: list[dict[str, Any]] = []

    for context in get_collection(
        artifacts,
        "process-logon-contexts"
    ):

        if not context.get("LogonContextFound"):
            continue

        process_record_id = context.get(
            "ProcessSecurityRecordId"
        )

        logon_record_id = context.get(
            "LogonSecurityRecordId"
        )

        if (
            process_record_id is None
            or logon_record_id is None
        ):
            continue

        relationships.append(
            {
                "relationship": "ExecutedUnder",

                "processSecurityRecordId":
                    process_record_id,

                "processId":
                    context.get("ProcessId"),

                "processName":
                    context.get("ProcessName"),

                "logonSecurityRecordId":
                    logon_record_id,

                "logonIdentity":
                    context.get("LogonIdentity"),

                "logonUserSid":
                    context.get("LogonUserSid"),

                "logonType":
                    context.get("LogonType"),

                "logonTime":
                    context.get("LogonTime"),

                "evidenceBasis":
                    context.get("EvidenceBasis"),
            }
        )

    return relationships


def build_process_session_relationships(
    artifacts: dict[str, Any]
) -> list[dict[str, Any]]:

    relationships: list[dict[str, Any]] = []

    for execution_context in get_collection(
        artifacts,
        "process-execution-contexts"
    ):

        process_record_id = execution_context.get(
            "ProcessSecurityRecordId"
        )

        lineage = execution_context.get(
            "ContextLineage"
        )

        if (
            process_record_id is None
            or not isinstance(lineage, list)
            or len(lineage) == 0
        ):
            continue

        root_process = lineage[0]

        session_matches = root_process.get(
            "WindowsSessionMatches"
        )

        if not isinstance(session_matches, list):
            continue

        for session in session_matches:

            relationships.append(
                {
                    "relationship": "OccurredWithin",

                    "processSecurityRecordId":
                        process_record_id,

                    "processId":
                        execution_context.get("ProcessId"),

                    "processName":
                        execution_context.get("ProcessName"),

                    "sessionId":
                        session.get("SessionId"),

                    "sessionUser":
                        session.get("User"),

                    "sessionLogonRecordId":
                        session.get("LogonRecordId"),

                    "sessionStart":
                        session.get("SessionStart"),

                    "sessionEnd":
                        session.get("SessionEnd"),

                    "sourceAddress":
                        session.get("SourceAddress"),

                    "evidenceBasis":
                        root_process.get(
                            "WindowsSessionEvidenceBasis"
                        ),
                }
            )

    return relationships


# ============================================================
# PAYLOAD BUILDING
# ============================================================

def build_evidence_payload(
    run_directory: Path
) -> dict[str, Any]:

    if not run_directory.exists():
        raise FileNotFoundError(
            f"HALON run directory does not exist: "
            f"{run_directory}"
        )

    if not run_directory.is_dir():
        raise NotADirectoryError(
            f"HALON run path is not a directory: "
            f"{run_directory}"
        )

    artifacts, artifact_index = (
        load_canonical_artifacts(
            run_directory
        )
    )

    manifest = get_object(
        artifacts,
        "manifest"
    )

    if manifest is None:
        raise FileNotFoundError(
            "HALON run does not contain "
            "a valid manifest.json."
        )

    event_process_relationships = (
        build_event_process_relationships(
            artifacts
        )
    )

    process_parent_relationships = (
        build_process_parent_relationships(
            artifacts
        )
    )

    process_logon_relationships = (
        build_process_logon_relationships(
            artifacts
        )
    )

    process_session_relationships = (
        build_process_session_relationships(
            artifacts
        )
    )

    payload = {

        # ----------------------------------------------------
        # PAYLOAD IDENTITY / PROVENANCE
        # ----------------------------------------------------

        "payloadMetadata": {

            "payloadSchemaVersion":
                PAYLOAD_SCHEMA_VERSION,

            "payloadBuilderVersion":
                PAYLOAD_BUILDER_VERSION,

            "generatedAtUtc":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "sourceRunId":
                run_directory.name,

            "sourceComputerName":
                manifest.get("ComputerName"),

            "sourceCollectionStart":
                manifest.get("CollectionStart"),

            "sourceCollectionEnd":
                manifest.get("CollectionEnd"),

            "sourceTimeZone":
                manifest.get("TimeZone"),

            "canonicalArtifactCount":
                len(artifacts),
        },


        # ----------------------------------------------------
        # PROVENANCE
        # ----------------------------------------------------

        "provenance": {

            "sourceManifest":
                manifest,

            "artifactIndex":
                artifact_index,
        },


        # ----------------------------------------------------
        # COLLECTION CAPABILITIES
        # ----------------------------------------------------

        "capabilities": {

            "processEvidence":
                get_object(
                    artifacts,
                    "process-evidence-capability"
                ),
        },


        # ----------------------------------------------------
        # CANONICAL EVIDENCE
        # ----------------------------------------------------

        "evidence": {

            "host": {

                "system":
                    get_object(
                        artifacts,
                        "system-info"
                    ),

                "disks":
                    get_collection(
                        artifacts,
                        "disks"
                    ),

                "services":
                    get_collection(
                        artifacts,
                        "services"
                    ),
            },

            "windowsEvents":
                get_collection(
                    artifacts,
                    "events"
                ),

            "processes":
                get_collection(
                    artifacts,
                    "process-events"
                ),

            "identityEvents":
                get_collection(
                    artifacts,
                    "identity-events"
                ),

            "sessions": {

                "current":
                    get_collection(
                        artifacts,
                        "current-sessions"
                    ),

                "windowsSessionEvents":
                    get_collection(
                        artifacts,
                        "windows-session-events"
                    ),
            },
        },


        # ----------------------------------------------------
        # EXPLICIT EVIDENCE RELATIONSHIPS
        # ----------------------------------------------------

        "relationships": {

            "eventToProcess":
                event_process_relationships,

            "processToParent":
                process_parent_relationships,

            "processToLogon":
                process_logon_relationships,

            "processToWindowsSession":
                process_session_relationships,
        },


        # ----------------------------------------------------
        # DETERMINISTIC RECONSTRUCTIONS
        # ----------------------------------------------------

        "reconstructions": {

            "identitySessions":
                get_collection(
                    artifacts,
                    "identity-sessions"
                ),

            "windowsSessions":
                get_collection(
                    artifacts,
                    "windows-sessions"
                ),

            "processLineages":
                get_collection(
                    artifacts,
                    "process-lineage"
                ),

            "processExecutionContexts":
                get_collection(
                    artifacts,
                    "process-execution-contexts"
                ),

            "timeline":
                get_collection(
                    artifacts,
                    "timeline"
                ),

            "incidentContexts":
                get_collection(
                    artifacts,
                    "incident-context"
                ),

            "incidentIdentities":
                get_collection(
                    artifacts,
                    "incident-identities"
                ),

            "windowsSessionsAtIncident":
                get_collection(
                    artifacts,
                    "windows-sessions-at-incident"
                ),

            "incidents":
                get_collection(
                    artifacts,
                    "incidents"
                ),
        },


        # ----------------------------------------------------
        # DETERMINISTIC SUMMARIES
        # ----------------------------------------------------

        "summaries": {

            "evidence":
                get_collection(
                    artifacts,
                    "evidence-summary"
                ),

            "events":
                get_collection(
                    artifacts,
                    "event-summary"
                ),
        },


        # ----------------------------------------------------
        # AGENT EXECUTION INFORMATION
        # Not system diagnostic evidence.
        # ----------------------------------------------------

        "agentDiagnostics": {

            "performance":
                get_object(
                    artifacts,
                    "performance"
                ),
        },


        # ----------------------------------------------------
        # RELATIONSHIP SUMMARY
        # ----------------------------------------------------

        "relationshipSummary": {

            "eventToProcess":
                len(
                    event_process_relationships
                ),

            "processToParent":
                len(
                    process_parent_relationships
                ),

            "processToLogon":
                len(
                    process_logon_relationships
                ),

            "processToWindowsSession":
                len(
                    process_session_relationships
                ),
        },
    }

    return payload


# ============================================================
# EXPORT
# ============================================================

def write_payload(
    payload: dict[str, Any],
    output_path: Path
) -> None:

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Build a portable HALON Evidence Engine "
            "Payload from a completed canonical "
            "evidence run."
        )
    )

    parser.add_argument(
        "--run-dir",
        required=True,
        type=Path,
        help=(
            "Completed HALON canonical "
            "evidence run directory."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Optional payload output path. "
            "Defaults to evidence-payload-v1.json "
            "inside the source run directory."
        ),
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    args = parse_arguments()

    run_directory = (
        args.run_dir.resolve()
    )

    output_path = (
        args.output.resolve()
        if args.output
        else run_directory
        / "evidence-payload-v1.json"
    )

    print()
    print(
        "======================================="
    )
    print(
        " HALON EVIDENCE PACKAGER"
    )
    print(
        "======================================="
    )
    print()

    print(
        f"Source run: {run_directory}"
    )

    print()

    payload = build_evidence_payload(
        run_directory
    )

    write_payload(
        payload,
        output_path
    )

    print(
        "Canonical artifacts loaded: "
        f"{payload['payloadMetadata']['canonicalArtifactCount']}"
    )

    print()

    print(
        "Relationships constructed:"
    )

    for (
        relationship_type,
        count
    ) in payload[
        "relationshipSummary"
    ].items():

        print(
            f"  {relationship_type}: {count}"
        )

    print()

    print(
        f"Evidence payload: {output_path}"
    )

    print()

    print(
        "HALON EVIDENCE PACKAGING COMPLETE"
    )

    print()


if __name__ == "__main__":
    main()