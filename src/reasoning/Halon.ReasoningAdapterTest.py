import importlib.util
import json
import sys
import time
from pathlib import Path

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

ADAPTER_PATH = Path(
    r"C:\Dev\halon\src\reasoning\Halon.EvidenceAdapter.py"
)

VALIDATOR_PATH = Path(
    r"C:\Dev\halon\src\reasoning\Halon.OutputValidator.py"
)

DEBUG_OUTPUT_PATH = Path(
    r"C:\Dev\halon\tests\reasoning-output"
    r"\crash-working-set.json"
)

VALIDATION_OUTPUT_PATH = Path(
    r"C:\Dev\halon\tests\reasoning-output"
    r"\crash-output-validation.json"
)

TARGET_PROCESS = "HalonCrashProbe.exe"


# ============================================================
# LOAD ADAPTER
# ============================================================

def load_adapter():

    spec = (
        importlib.util.spec_from_file_location(
            "halon_evidence_adapter",
            ADAPTER_PATH
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise RuntimeError(
            "Could not load HALON Evidence Adapter."
        )

    module = (
        importlib.util.module_from_spec(
            spec
        )
    )

    spec.loader.exec_module(
        module
    )

    return module

def load_validator():

    spec = (
        importlib.util.spec_from_file_location(
            "halon_output_validator",
            VALIDATOR_PATH
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise RuntimeError(
            "Could not load HALON Output Validator."
        )

    module = (
        importlib.util.module_from_spec(
            spec
        )
    )

    spec.loader.exec_module(
        module
    )

    return module

# ============================================================
# PROMPTS
# ============================================================

def build_system_prompt() -> str:

    return """
You are the HALON Reasoning Engine.

You receive reasoning-ready evidence produced deterministically
from HALON canonical Windows evidence.

The evidence adapter has already converted low-level HALON
records into semantically explicit timelines, relationships,
process ancestry, security context, session context, and
technical observations.


EVIDENCE RULES

1. Treat supplied HALON evidence as authoritative for what HALON
   observed or deterministically correlated.

2. Do not invent evidence.

3. Follow the supplied evidence-basis definitions exactly.

4. Preserve the direction of explicit HALON relationships.

   Do not reconstruct a relationship differently from the
   source, relationship, and target supplied by HALON.

5. A lineage traversal termination applies to the end of the
   ancestry traversal.

   It does not mean that the target process lacked a parent.

6. Correlation does not establish causation, human action,
   intent, or responsibility.

7. Security context does not prove that a human manually
   launched a process.

8. Preserve numerical values and units exactly.


TECHNICAL INTERPRETATION RULES

9. Technical interpretation requires authoritative reference
   material.

10. In technicalObservations, observedValue means HALON actually
    observed that value in the supplied machine evidence.

11. interpretationStatus = AuthoritativeReferenceRequired means
    the observed value is known, but its technical significance
    has not yet been established through authoritative reference
    material.

    Do not describe such a value as missing, absent, unavailable,
    or not provided.

12. Do not assign specific technical meaning to unresolved
    technical observations from pretrained memory.


KNOWLEDGE REQUEST RULES

13. Request authoritative knowledge only when technical
    interpretation is actually unresolved and materially useful
    to answering the question.

14. technicalObservations with:

    interpretationStatus = AuthoritativeReferenceRequired

    are explicit candidates for KNOWLEDGE REQUIRED.

    Deterministically reconstructed HALON evidence such as:
    - process ancestry,
    - parent relationships,
    - security context,
    - Windows session membership,
    - timestamps,
    - record identifiers

    does not require authoritative reference material merely
    because it appears in the evidence.

    Do not request external knowledge to reinterpret evidence
    that HALON has already deterministically established.

    Only request knowledge about such evidence if the user's
    question specifically requires understanding the technical
    significance of that relationship or Windows behavior.


HYPOTHESIS RULES

15. Do not create speculative hypotheses merely to populate the
    HYPOTHESES section.

16. A hypothesis must propose an explanation for unresolved
    observed behavior AND must have positive supporting evidence.

    Mere possibility is not sufficient.

    A fact being compatible with an explanation does not make
    that explanation an evidence-supported hypothesis.

    Do not hypothesize human initiation from security identity,
    logon correlation, Windows session membership, or process
    ancestry alone.

    Human initiation may only appear as a hypothesis when HALON
    supplies additional evidence that positively supports human
    initiation.

    Do not use HYPOTHESES to restate established evidence.

    For example, these are evidence rather than hypotheses:
    - a process occurred within a Windows session,
    - a process had a reconstructed parent,
    - a process had reconstructed ancestors,
    - an event occurred shortly after process creation.

17. Presence, compatibility, temporal association, or an already
    established HALON relationship is not sufficient support for
    a diagnostic hypothesis.

    An established HALON relationship belongs under
    RECONSTRUCTED EVIDENCE unless it provides positive support
    for a separate unresolved explanation.

    Do not turn an established relationship into a hypothesis.

    In particular:
    - event-to-process correlation does not itself constitute a
      failure hypothesis,
    - process ancestry alone does not implicate an ancestor,
    - a faulting module alone does not establish a root cause,
    - an exception code alone does not establish a failure
      mechanism,
    - temporal proximity alone does not establish causation.

18. If the available evidence does not support a specific
    failure mechanism, use the required fallback statement
    defined under HYPOTHESES in the output format below.


OUTPUT DISCIPLINE

19. interpretationBoundaries are global constraints.

    Do not repeat them alongside every individual piece of
    reconstructed evidence.

    Use them when relevant under LIMITATIONS.

20. Prefer a concise answer.

    Tell the evidence story once and do not repeat the same fact
    across multiple sections.


OUTPUT FORMAT

Respond using exactly these four sections, in this order:


RECONSTRUCTED EVIDENCE

Present the observable machine story.

Prefer chronological order when timestamps are available.

Include important evidence identifiers and deterministic
relationships when useful.

Preserve relationship direction exactly as supplied by HALON.

Technical observations associated with a Windows event must be
described as values recorded by that event.

Do not describe an exception code, faulting module, fault offset,
or similar event field as an inherent property of the referenced
process unless HALON explicitly establishes that relationship.

Do not interpret unresolved technical identifiers here.


HYPOTHESES

List only evidence-supported explanations for unresolved
observed behavior.

Do not restate established evidence as a hypothesis.

HYPOTHESES must never be empty.

If no evidence-supported explanatory hypothesis exists, write
exactly:

"The available evidence does not presently support a more
specific failure hypothesis."

Place that statement under HYPOTHESES only.

Do not place that fallback statement under LIMITATIONS.


KNOWLEDGE REQUIRED

List only unresolved technical interpretations that require
authoritative reference material and would materially improve
the answer.

Prefer items explicitly marked:

interpretationStatus = AuthoritativeReferenceRequired

Do not request knowledge merely to reinterpret deterministic
HALON relationships that are already established.

Do not answer unresolved technical questions unless referenced
knowledge was actually supplied.


LIMITATIONS

State what the available evidence cannot establish.

Include material uncertainty involving causation, human intent,
responsibility, missing telemetry, or other evidentiary limits.

Do not repeat the HYPOTHESES fallback statement here.
""".strip()


def build_user_prompt(
    working_set: dict
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

Use the reasoning-ready HALON evidence below.

Reconstruct the observable story once, preferably in
chronological order.

Use HALON's explicit relationships rather than deriving new
relationships from raw fields.

Do not interpret unresolved technical identifiers without an
authoritative reference.


REASONING-READY HALON EVIDENCE

{evidence_json}
""".strip()


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print()
    print("=======================================")
    print(" HALON REASONING ENGINE")
    print(" REASONING-READY EVIDENCE TEST")
    print("=======================================")
    print()

# --------------------------------------------------------
# VALIDATE
# --------------------------------------------------------

    for path, name in (
        (MODEL_PATH, "model"),
        (PAYLOAD_PATH, "payload"),
        (ADAPTER_PATH, "adapter"),
        (VALIDATOR_PATH, "validator"),
    ):

        if not path.exists():

            print(
                f"FAIL: HALON {name} not found:"
            )
            print(path)
            sys.exit(1)

# --------------------------------------------------------
# BUILD REASONING-READY EVIDENCE
# --------------------------------------------------------

    try:

        adapter = load_adapter()

        payload = (
            adapter.load_payload(
                PAYLOAD_PATH
            )
        )

        working_set = (
            adapter.build_crash_working_set(
                payload,
                TARGET_PROCESS
            )
        )

    except Exception as error:

        print(
            "FAIL: Evidence adapter failed."
        )
        print()
        print(error)
        sys.exit(1)

# --------------------------------------------------------
# SAVE DEBUG COPY
# --------------------------------------------------------

    DEBUG_OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with DEBUG_OUTPUT_PATH.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            working_set,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        "Reasoning-ready evidence constructed."
    )

    print(
        f"Debug evidence: "
        f"{DEBUG_OUTPUT_PATH}"
    )

    print()

    target = working_set.get(
        "targetProcess",
        {}
    )

    print(
        "Target Process: "
        f"{target.get('processFileName')}"
    )

    print(
        "Process Record ID: "
        f"{target.get('processSecurityRecordId')}"
    )

    print()

# --------------------------------------------------------
# LOAD MODEL
# --------------------------------------------------------

    print("Loading Phi-4 Mini...")
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
            "FAIL: Model load failed."
        )
        print()
        print(error)
        sys.exit(1)

    print(
        f"Model loaded in "
        f"{time.perf_counter() - load_start:.2f} seconds."
    )

    print()

# --------------------------------------------------------
# INFERENCE
# --------------------------------------------------------

    print(
        "Asking Phi:"
    )
    print()
    print(
        "What happened to HalonCrashProbe.exe?"
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
                            build_system_prompt(),
                    },
                    {
                        "role": "user",
                        "content":
                            build_user_prompt(
                                working_set
                            ),
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
            "FAIL: Unexpected model response."
        )
        print()
        print(response)
        sys.exit(1)


# --------------------------------------------------------
# PRINT REASONING RESPONSE
# --------------------------------------------------------

    print(answer)

    print()
    print(
        "---------------------------------------"
    )
    print()


# --------------------------------------------------------
# VALIDATE REASONING OUTPUT CONTRACT
# --------------------------------------------------------

    try:

        validator = load_validator()

        validation = (
            validator.validate_reasoning_output(
                answer
            )
        )

    except Exception as error:

        print(
            "FAIL: Reasoning output "
            "validation failed."
        )
        print()
        print(error)
        sys.exit(1)


# --------------------------------------------------------
# SAVE VALIDATION ARTIFACT
# --------------------------------------------------------

    VALIDATION_OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with VALIDATION_OUTPUT_PATH.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            validation,
            file,
            indent=2,
            ensure_ascii=False,
        )

# --------------------------------------------------------
# PRINT VALIDATION RESULT
# --------------------------------------------------------

    print(
        "======================================="
    )
    print(
        " REASONING OUTPUT CONTRACT"
    )
    print(
        "======================================="
    )
    print()


    if validation.get(
        "isValid"
    ):

        print(
            "PASS: Reasoning output "
            "matches the HALON contract."
        )

    else:

        print(
            "FAIL: Reasoning output "
            "violated the HALON contract."
        )

        print()

        for violation in validation.get(
            "violations",
            []
        ):

            print(
                f"- {violation.get('code')}: "
                f"{violation.get('message')}"
            )


    print()

    print(
        "Expected Sections:"
    )

    for section in validation.get(
        "expectedSections",
        []
    ):

        print(
            f"  - {section}"
        )


    print()

    print(
        "Observed Sections:"
    )

    for section in validation.get(
        "observedSections",
        []
    ):

        print(
            f"  - {section}"
        )


    print()

    print(
        f"Validation artifact: "
        f"{VALIDATION_OUTPUT_PATH}"
    )

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
        " ADAPTER TEST COMPLETE"
    )
    print(
        "======================================="
    )
    print()


if __name__ == "__main__":
    main()