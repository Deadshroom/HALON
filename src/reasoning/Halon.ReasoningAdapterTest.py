import importlib.util
import json
import sys
import time
from pathlib import Path


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

REASONING_ENGINE_PATH = Path(
    r"C:\Dev\halon\src\reasoning\Halon.ReasoningEngine.py"
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

QUESTION = (
    "What happened to HalonCrashProbe.exe?"
)


# ============================================================
# MODULE LOADING
# ============================================================

def load_module(
    module_name: str,
    module_path: Path,
):

    spec = (
        importlib.util.spec_from_file_location(
            module_name,
            module_path,
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise RuntimeError(
            f"Could not load HALON module: "
            f"{module_path}"
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
        " REASONING-READY EVIDENCE TEST"
    )
    print(
        "======================================="
    )
    print()

    # --------------------------------------------------------
    # VALIDATE REQUIRED COMPONENTS
    # --------------------------------------------------------

    for path, name in (

        (
            MODEL_PATH,
            "model",
        ),

        (
            PAYLOAD_PATH,
            "payload",
        ),

        (
            ADAPTER_PATH,
            "evidence adapter",
        ),

        (
            REASONING_ENGINE_PATH,
            "reasoning engine",
        ),

        (
            VALIDATOR_PATH,
            "output validator",
        ),
    ):

        if not path.exists():

            print(
                f"FAIL: HALON {name} not found:"
            )

            print(
                path
            )

            sys.exit(1)

    # --------------------------------------------------------
    # LOAD HALON COMPONENTS
    # --------------------------------------------------------

    try:

        adapter = load_module(
            "halon_evidence_adapter",
            ADAPTER_PATH,
        )

        reasoning_engine_module = (
            load_module(
                "halon_reasoning_engine",
                REASONING_ENGINE_PATH,
            )
        )

        validator = load_module(
            "halon_output_validator",
            VALIDATOR_PATH,
        )

    except Exception as error:

        print(
            "FAIL: HALON component loading failed."
        )

        print()
        print(
            error
        )

        sys.exit(1)

    # --------------------------------------------------------
    # BUILD REASONING-READY EVIDENCE
    # --------------------------------------------------------

    try:

        payload = (
            adapter.load_payload(
                PAYLOAD_PATH
            )
        )

        working_set = (
            adapter.build_crash_working_set(
                payload,
                TARGET_PROCESS,
            )
        )

    except Exception as error:

        print(
            "FAIL: Evidence adapter failed."
        )

        print()
        print(
            error
        )

        sys.exit(1)

    # --------------------------------------------------------
    # SAVE DEBUG COPY
    # --------------------------------------------------------

    DEBUG_OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with DEBUG_OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            working_set,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print(
        "Reasoning-ready evidence constructed."
    )

    print(
        f"Debug evidence: "
        f"{DEBUG_OUTPUT_PATH}"
    )

    print()

    target = (
        working_set.get(
            "targetProcess",
            {},
        )
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
    # INITIALIZE REASONING ENGINE
    # --------------------------------------------------------

    print(
        "Initializing HALON Reasoning Engine..."
    )

    print()

    engine_load_start = (
        time.perf_counter()
    )

    try:

        reasoning_engine = (
            reasoning_engine_module
            .HalonReasoningEngine(
                model_path=MODEL_PATH,
                context_size=8192,
                thread_count=8,
            )
        )

    except Exception as error:

        print(
            "FAIL: HALON Reasoning Engine "
            "initialization failed."
        )

        print()
        print(
            error
        )

        sys.exit(1)

    engine_load_seconds = (
        time.perf_counter()
        - engine_load_start
    )

    print(
        "Reasoning Engine initialized in "
        f"{engine_load_seconds:.2f} seconds."
    )

    print()

    # --------------------------------------------------------
    # REASON
    # --------------------------------------------------------

    print(
        "Asking Phi:"
    )

    print()
    print(
        QUESTION
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

        answer = (
            reasoning_engine.reason(
                question=QUESTION,
                evidence=working_set,
                knowledge=None,
                max_tokens=1200,
            )
        )

    except Exception as error:

        print(
            "FAIL: HALON reasoning failed."
        )

        print()
        print(
            error
        )

        sys.exit(1)

    inference_seconds = (
        time.perf_counter()
        - inference_start
    )

    # --------------------------------------------------------
    # PRINT REASONING RESPONSE
    # --------------------------------------------------------

    print(
        answer
    )

    print()
    print(
        "---------------------------------------"
    )

    print()

    # --------------------------------------------------------
    # VALIDATE REASONING OUTPUT CONTRACT
    # --------------------------------------------------------

    try:

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
        print(
            error
        )

        sys.exit(1)

    # --------------------------------------------------------
    # SAVE VALIDATION ARTIFACT
    # --------------------------------------------------------

    VALIDATION_OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with VALIDATION_OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
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
        "Reasoning completed in "
        f"{inference_seconds:.2f} seconds."
    )

    print()

    print(
        "======================================="
    )

    print(
        " REASONING ENGINE TEST COMPLETE"
    )

    print(
        "======================================="
    )

    print()


if __name__ == "__main__":
    main()