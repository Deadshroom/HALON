import json
import sys
import time
from pathlib import Path
from typing import Any

from llama_cpp import Llama


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = Path(
    r"C:\Dev\halon\models\Phi-4-mini-instruct-Q4_K_M.gguf"
)

PAYLOAD_PATH = Path(
    r"C:\Dev\halon\output\WADESYSTEM_20260828_184723"
    r"\evidence-payload-v1.json"
)

TARGET_PROCESS = "HalonCrashProbe.exe"


# ============================================================
# HELPERS
# ============================================================

def load_json(path: Path) -> Any:
    with path.open(
        "r",
        encoding="utf-8-sig"
    ) as file:
        return json.load(file)


def find_latest_crash_relationship(
    payload: dict[str, Any]
) -> dict[str, Any] | None:

    relationships = (
        payload
        .get("relationships", {})
        .get("eventToProcess", [])
    )

    matches = [
        relationship
        for relationship in relationships
        if TARGET_PROCESS.lower()
        in str(
            relationship.get(
                "referencedProcessName",
                ""
            )
        ).lower()
    ]

    if not matches:
        return None

    matches.sort(
        key=lambda item: str(
            item.get("eventTime", "")
        ),
        reverse=True,
    )

    return matches[0]


def find_process(
    payload: dict[str, Any],
    process_record_id: Any
) -> dict[str, Any] | None:

    processes = (
        payload
        .get("evidence", {})
        .get("processes", [])
    )

    for process in processes:

        if str(
            process.get("SecurityRecordId")
        ) == str(process_record_id):

            return process

    return None


def find_event(
    payload: dict[str, Any],
    event_record_id: Any
) -> dict[str, Any] | None:

    events = (
        payload
        .get("evidence", {})
        .get("windowsEvents", [])
    )

    for event in events:

        if str(
            event.get("RecordId")
        ) == str(event_record_id):

            return event

    return None


def find_relationship(
    payload: dict[str, Any],
    relationship_type: str,
    process_record_id: Any
) -> dict[str, Any] | None:

    relationships = (
        payload
        .get("relationships", {})
        .get(relationship_type, [])
    )

    for relationship in relationships:

        record_id = (
            relationship.get(
                "childProcessSecurityRecordId"
            )
            if relationship_type
            == "processToParent"
            else relationship.get(
                "processSecurityRecordId"
            )
        )

        if str(record_id) == str(
            process_record_id
        ):
            return relationship

    return None


def find_process_lineage(
    payload: dict[str, Any],
    process_record_id: Any
) -> dict[str, Any] | None:

    lineages = (
        payload
        .get("reconstructions", {})
        .get("processLineages", [])
    )

    for lineage in lineages:

        if str(
            lineage.get(
                "ProcessSecurityRecordId"
            )
        ) == str(process_record_id):

            return lineage

    return None


# ============================================================
# WORKING EVIDENCE SET
# ============================================================

def build_crash_working_set(
    payload: dict[str, Any]
) -> dict[str, Any]:

    crash_relationship = (
        find_latest_crash_relationship(
            payload
        )
    )

    if crash_relationship is None:
        raise RuntimeError(
            "No HalonCrashProbe.exe "
            "event/process relationship found."
        )

    process_record_id = (
        crash_relationship[
            "processSecurityRecordId"
        ]
    )

    event = find_event(
        payload,
        crash_relationship.get(
            "eventRecordId"
        ),
    )

    process = find_process(
        payload,
        process_record_id,
    )

    parent_relationship = (
        find_relationship(
            payload,
            "processToParent",
            process_record_id,
        )
    )

    logon_relationship = (
        find_relationship(
            payload,
            "processToLogon",
            process_record_id,
        )
    )

    session_relationship = (
        find_relationship(
            payload,
            "processToWindowsSession",
            process_record_id,
        )
    )

    lineage = find_process_lineage(
        payload,
        process_record_id,
    )

    return {
         "evidenceSemantics":
            build_evidence_semantics(),

        "questionTarget": {
            "processName":
                TARGET_PROCESS,
        },

        "event": event,

        "eventToProcessRelationship":
            crash_relationship,

        "historicalProcess":
            process,

        "directParentRelationship":
            parent_relationship,

        "securityLogonRelationship":
            logon_relationship,

        "windowsSessionRelationship":
            session_relationship,

        "processLineage":
            lineage,
    }

def build_evidence_semantics() -> dict[str, Any]:

    return {
        "generalRules": {

            "correlationIsNotCausation": (
                "HALON correlations establish observable relationships "
                "between Windows evidence records. They do not by themselves "
                "establish root cause, human intent, or responsibility."
            ),

            "missingEvidence": (
                "Failure to establish a relationship means HALON could not "
                "establish that relationship from the available evidence. "
                "It does not prove that the relationship did not exist."
            ),

            "identityMeaning": (
                "A process security identity describes the Windows security "
                "context under which Windows recorded the process executing. "
                "It does not prove that a human directly launched the process."
            ),
        },

        "fields": {

            "ProcessAgeAtEventSeconds": (
                "Elapsed time in seconds between the creation of the matched "
                "historical process and the occurrence of the referenced "
                "Windows event. Example: 0.054 seconds means 54 milliseconds. "
                "This is not system uptime."
            ),

            "SeverityScore": (
                "A HALON normalized severity value used to consistently "
                "represent event severity. It is not itself a causal score "
                "or measure of diagnostic importance."
            ),

            "FaultingModule": (
                "The module Windows recorded as the faulting module in the "
                "event. This does not by itself establish the root cause."
            ),

            "ExceptionCode": (
                "The exception code recorded by Windows for the event. "
                "HALON treats the code as an observation. Its technical "
                "meaning must be interpreted separately."
            ),
        },

        "correlations": {

            "ProcessIdAndProcessName": {
                "means": (
                    "HALON matched an event's referenced process to a "
                    "historical process creation record using compatible "
                    "process ID, process name, and chronology."
                ),

                "doesNotMean": (
                    "The matched process caused the event, or that a human "
                    "intentionally caused the event."
                ),
            },

            "ParentProcessIdAndName": {
                "means": (
                    "HALON matched a child process to an earlier historical "
                    "process creation record using the recorded parent process "
                    "ID, compatible parent process name, and chronology."
                ),

                "doesNotMean": (
                    "A human directly launched the child process or that the "
                    "parent process caused a later failure."
                ),
            },

            "SecurityLogonIdMatch": {
                "means": (
                    "HALON matched the process security context to a Windows "
                    "security logon record using the Logon ID and chronology."
                ),

                "doesNotMean": (
                    "The associated human account personally initiated the "
                    "process."
                ),
            },

            "ExactSubjectIdentityAndSessionWindow": {
                "means": (
                    "The process subject identity exactly matched the Windows "
                    "session user and the process occurred within the observed "
                    "session time interval."
                ),

                "doesNotMean": (
                    "The session user manually launched or intentionally "
                    "caused the process activity."
                ),
            },

            "NoHistoricalParentProcessMatch": {
                "means": (
                    "HALON could not establish the historical parent process "
                    "from the process creation evidence available inside the "
                    "collection window."
                ),

                "doesNotMean": (
                    "The process had no parent, was directly created by the "
                    "system, or originated from an unknown process."
                ),
            },
        },
    }
# ============================================================
# PROMPT
# ============================================================

def build_system_prompt() -> str:

    return """
You are the HALON Reasoning Engine.

HALON provides deterministic Windows evidence that has already
been collected, normalized, reconstructed, and correlated.

Your job is to interpret that evidence without changing what
the evidence actually establishes.

EVIDENCE RULES

1. Treat supplied HALON evidence as authoritative for what
   HALON observed or deterministically correlated.

2. Never invent events, processes, identities, timestamps,
   record IDs, relationships, system state, or telemetry.

3. Preserve exact numerical values and units.

4. HALON correlation establishes an observable relationship.
   Correlation alone does not establish causation, intent,
   responsibility, or human action.

5. A missing relationship means HALON could not establish that
   relationship from the available evidence.

   Missing evidence is NEVER itself a cause of an event.

6. A Windows security context identifies the security context
   under which Windows recorded a process executing.

   It does not establish:
   - that a human manually launched the process,
   - that the account had all necessary permissions,
   - that the account caused later activity.

7. A process-parent relationship establishes recorded process
   ancestry. It does not establish that the parent caused a
   later failure.

8. Words such as:
   - caused,
   - responsible for,
   - intentionally,
   - initiated by,
   - due to

   require evidence or referenced technical knowledge that
   supports that claim.

TECHNICAL INTERPRETATION RULES

9. Technical interpretation requires authoritative reference
   material.

10. In technicalObservations, observedValue means HALON actually
    observed that value in the supplied machine evidence.

11. interpretationStatus = AuthoritativeReferenceRequired means
    the value is known, but its technical significance has not
    yet been established through authoritative reference
    material.

    Do not describe such a value as missing, absent, unavailable,
    or not provided.

    Report the observed value exactly and place its unresolved
    technical significance under KNOWLEDGE REQUIRED.

12. Do not assign specific technical meaning to unresolved
    technical observations from pretrained memory.

13. When referenced knowledge is eventually supplied, distinguish:

    HALON EVIDENCE:
        what occurred on the machine.

    AUTHORITATIVE REFERENCE:
        what a documented technical value or behavior means.

    REASONING:
        what the combination of those two supports.

REASONING RULES

14. Do not create hypotheses merely because a HYPOTHESES section
    exists.

15. A hypothesis must be connected to something actually present
    in the supplied evidence.

16. If the evidence supports no useful diagnostic hypothesis,
    explicitly state that additional technical knowledge or
    evidence is required.

17. Do not duplicate the same facts across multiple output
    sections.

18. Process ancestry alone is not evidence that an ancestor contributed to a later failure. 
    Do not introduce an ancestor into HYPOTHESES unless another 
    supplied observation connects it to the failure.

OUTPUT FORMAT

Respond using exactly these sections:

RECONSTRUCTED EVIDENCE

Present the observable story once.

Prefer chronological order when timestamps are available.

Include important evidence identifiers and deterministic
relationships when useful.

Do not interpret undocumented technical codes here.


HYPOTHESES

List only reasonable diagnostic possibilities supported by the
available evidence.

Clearly distinguish hypothesis from established fact.

If none are supportable, say so.


KNOWLEDGE REQUIRED

List the specific technical questions that require authoritative
reference material before stronger reasoning can occur.

Examples include:
- meaning of an exception code,
- meaning of an Event ID,
- significance of a faulting module,
- documented behavior of a Windows component.

Do not answer those questions unless referenced knowledge was
actually supplied.


LIMITATIONS

State what the available evidence cannot establish.

Include important uncertainty around causation, intent, missing
telemetry, or unresolved technical meaning.
""".strip()

def build_user_prompt(
    working_set: dict[str, Any]
) -> str:

    evidence_json = json.dumps(
        working_set,
        indent=2,
        ensure_ascii=False,
    )

    return f"""
QUESTION

What happened to HalonCrashProbe.exe?


TASK

Reconstruct the observable sequence using the supplied HALON
evidence.

Tell the story of the evidence once rather than repeating the
same facts under different headings.

Where HALON provides a correlation, preserve the stated evidence
basis.

Where a technical value requires documentation to understand,
identify that need under KNOWLEDGE REQUIRED rather than supplying
an unsupported technical interpretation.

Do not attempt to determine human intent unless the evidence
explicitly establishes it.


HALON EVIDENCE

{evidence_json}
""".strip()


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print()
    print(
        "======================================="
    )
    print(
        " HALON REASONING ENGINE"
    )
    print(
        " CONTROLLED CRASH BASELINE"
    )
    print(
        "======================================="
    )
    print()

    # --------------------------------------------------------
    # VALIDATE INPUTS
    # --------------------------------------------------------

    if not MODEL_PATH.exists():

        print(
            "FAIL: Model file not found:"
        )
        print(MODEL_PATH)
        sys.exit(1)

    if not PAYLOAD_PATH.exists():

        print(
            "FAIL: Evidence payload not found:"
        )
        print(PAYLOAD_PATH)
        sys.exit(1)

    # --------------------------------------------------------
    # LOAD PAYLOAD
    # --------------------------------------------------------

    print(
        f"Payload: {PAYLOAD_PATH.name}"
    )
    print()

    payload = load_json(
        PAYLOAD_PATH
    )

    # --------------------------------------------------------
    # BUILD WORKING SET
    # --------------------------------------------------------

    try:

        working_set = (
            build_crash_working_set(
                payload
            )
        )

    except Exception as error:

        print(
            "FAIL: Could not build "
            "crash evidence working set."
        )
        print()
        print(error)
        sys.exit(1)

    crash_relationship = (
        working_set[
            "eventToProcessRelationship"
        ]
    )

    print(
        "Working evidence set constructed."
    )

    print()

    print(
        "Event Record ID: "
        f"{crash_relationship.get('eventRecordId')}"
    )

    print(
        "Process Record ID: "
        f"{crash_relationship.get('processSecurityRecordId')}"
    )

    print(
        "Evidence Basis: "
        f"{crash_relationship.get('evidenceBasis')}"
    )

    print()

    # --------------------------------------------------------
    # LOAD MODEL
    # --------------------------------------------------------

    print(
        "Loading Phi-4 Mini..."
    )
    print()

    load_start = time.perf_counter()

    try:

        model = Llama(
            model_path=str(
                MODEL_PATH
            ),
            n_ctx=8192,
            n_threads=8,
            verbose=False,
        )

    except Exception as error:

        print(
            "FAIL: Model could not be loaded."
        )
        print()
        print(error)
        sys.exit(1)

    load_seconds = (
        time.perf_counter()
        - load_start
    )

    print(
        f"Model loaded in "
        f"{load_seconds:.2f} seconds."
    )

    print()

    # --------------------------------------------------------
    # REASON
    # --------------------------------------------------------

    system_prompt = (
        build_system_prompt()
    )

    user_prompt = (
        build_user_prompt(
            working_set
        )
    )

    print(
        "Asking Phi:"
    )
    print()

    print(
        "What happened to "
        "HalonCrashProbe.exe?"
    )

    print()
    print(
        "---------------------------------------"
    )
    print()

    inference_start = (
        time.perf_counter()
    )

    try:

        response = (
            model.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content":
                            system_prompt,
                    },
                    {
                        "role": "user",
                        "content":
                            user_prompt,
                    },
                ],
                temperature=0.1,
                max_tokens=1200,
            )
        )

    except Exception as error:

        print(
            "FAIL: Reasoning inference failed."
        )
        print()
        print(error)
        sys.exit(1)

    inference_seconds = (
        time.perf_counter()
        - inference_start
    )

    # --------------------------------------------------------
    # EXTRACT RESPONSE
    # --------------------------------------------------------

    try:

        answer = (
            response[
                "choices"
            ][0][
                "message"
            ][
                "content"
            ]
        ).strip()

    except Exception:

        print(
            "FAIL: Unexpected model "
            "response structure."
        )

        print()
        print(response)
        sys.exit(1)

    print(answer)

    print()
    print(
        "---------------------------------------"
    )
    print()

    print(
        f"Reasoning completed in "
        f"{inference_seconds:.2f} seconds."
    )

    usage = response.get(
        "usage",
        {}
    )

    if usage:

        print()

        print(
            "Prompt tokens: "
            f"{usage.get('prompt_tokens')}"
        )

        print(
            "Completion tokens: "
            f"{usage.get('completion_tokens')}"
        )

        print(
            "Total tokens: "
            f"{usage.get('total_tokens')}"
        )

    print()
    print(
        "======================================="
    )
    print(
        " REASONING TEST COMPLETE"
    )
    print(
        "======================================="
    )
    print()


if __name__ == "__main__":
    main()