import importlib.util
import json
import sys
import time

from datetime import datetime
from pathlib import Path


QUESTIONS = [
    {
        "question":
            "What PowerShell activity occurred on this machine?",

        "expectedFamily":
            "processes",

        "expectCompleteEnumeration":
            True,
    },
    {
        "question":
            "Who was logged into this machine?",

        "expectedFamily":
            "windowsSessions",

        "expectCompleteEnumeration":
            True,
    },
    {
        "question":
            (
                "Was process creation evidence available "
                "during this collection?"
            ),

        "expectedFamily":
            "processEvidenceCapability",

        "expectCompleteEnumeration":
            None,
    },
]


def load_module(
    name: str,
    path: Path,
):

    spec = (
        importlib.util.spec_from_file_location(
            name,
            path,
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):

        raise RuntimeError(
            f"Could not load HALON module: {path}"
        )

    module = (
        importlib.util.module_from_spec(
            spec
        )
    )

    sys.modules[
        name
    ] = module

    spec.loader.exec_module(
        module
    )

    return module


def main() -> int:

    repo_root = Path(
        r"C:\Dev\halon"
    )

    reasoning_path = (
        repo_root
        / "src"
        / "reasoning"
        / "Halon.ReasoningEngine.py"
    )

    database_path = (
        repo_root
        / "data"
        / "knowledge"
    )

    model_path = (
        repo_root
        / "models"
        / "Qwen3-8B-Q4_K_M.gguf"
    )

    output_dir = (
        repo_root
        / "output"
        / "regression"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for path, label in (
        (reasoning_path, "Reasoning Engine"),
        (database_path, "Knowledge database"),
        (model_path, "Reasoning model"),
    ):

        if not path.exists():

            raise FileNotFoundError(
                f"{label} not found: {path}"
            )

    print()
    print(
        "============================================================"
    )
    print(
        " HALON KNOWLEDGE -> REASONING INTEGRATION"
    )
    print(
        "============================================================"
    )
    print()
    print(
        f"Knowledge database: {database_path}"
    )
    print(
        f"Reasoning model:    {model_path.name}"
    )
    print()

    module = load_module(
        "halon_reasoning_engine",
        reasoning_path,
    )

    print(
        "Loading Knowledge Engine + reasoning model..."
    )
    print()

    load_started = time.perf_counter()

    engine = (
        module.HalonReasoningEngine(
            model_path=
                model_path,

            knowledge_database_path=
                database_path,

            context_size=
                8192,

            thread_count=
                1,

            family_limit=
                2,

            per_family_limit=
                3,
        )
    )

    print(
        "HALON initialized in "
        f"{time.perf_counter() - load_started:.2f}s."
    )
    print()

    results = []
    retrieval_pass = 0
    completeness_pass = 0
    completeness_total = 0

    for index, case in enumerate(
        QUESTIONS,
        start=1,
    ):

        question = case[
            "question"
        ]

        expected_family = case[
            "expectedFamily"
        ]

        expected_complete = case.get(
            "expectCompleteEnumeration"
        )

        print(
            "------------------------------------------------------------"
        )
        print(
            f"QUESTION {index}"
        )
        print(
            question
        )
        print()

        started = time.perf_counter()

        result = (
            engine.ask_evidence(
                question=
                    question,

                reasoning_max_tokens=
                    900,
            )
        )

        elapsed = (
            time.perf_counter()
            - started
        )

        evidence = result.get(
            "selectedEvidence",
            {},
        )

        retrieval = evidence.get(
            "retrieval",
            {},
        )

        selected_families = [
            item.get(
                "family"
            )
            for item in retrieval.get(
                "selectedFamilies",
                [],
            )
        ]

        passed = (
            expected_family
            in selected_families
        )

        if passed:
            retrieval_pass += 1

        status = (
            "PASS"
            if passed
            else "WARN"
        )

        actual_complete = retrieval.get(
            "completeForQuestion"
        )

        if expected_complete is None:

            completeness_status = (
                "N/A"
            )

        else:

            completeness_total += 1

            completeness_ok = (
                actual_complete
                is expected_complete
            )

            if completeness_ok:

                completeness_pass += 1

            completeness_status = (
                "PASS"
                if completeness_ok
                else "WARN"
            )

        print(
            "Retrieved families: "
            + ", ".join(
                str(item)
                for item in selected_families
            )
        )

        print(
            f"Expected family:   {expected_family}"
        )

        print(
            f"Retrieval:         {status}"
        )

        print(
            "Records supplied:  "
            f"{retrieval.get('recordCount', 0)}"
        )

        print(
            "Enumeration:       "
            f"{retrieval.get('enumerationRequested')}"
        )

        print(
            "Complete:          "
            f"{retrieval.get('completeForQuestion')} "
            f"({completeness_status})"
        )

        coverage = retrieval.get(
            "familyCoverage",
            {},
        )

        for family, family_coverage in coverage.items():

            print(
                "Coverage:          "
                f"{family} | "
                f"{family_coverage.get('mode')} | "
                f"details="
                f"{family_coverage.get('returnedDetailCount')} | "
                f"available="
                f"{family_coverage.get('availableRecordCount')} | "
                f"matched="
                f"{family_coverage.get('matchedRecordCount')} | "
                f"complete="
                f"{family_coverage.get('complete')} | "
                f"detailComplete="
                f"{family_coverage.get('detailComplete')}"
            )

        print(
            f"Elapsed:           {elapsed:.2f}s"
        )

        print()
        print(
            "HALON ANSWER"
        )
        print(
            "------------------------------------------------------------"
        )
        print(
            result.get(
                "answer",
                "",
            )
        )
        print()

        results.append(
            {
                "question":
                    question,

                "expectedFamily":
                    expected_family,

                "retrievalStatus":
                    status,

                "completenessStatus":
                    completeness_status,

                "completeForQuestion":
                    actual_complete,

                "selectedFamilies":
                    selected_families,

                "elapsedSeconds":
                    elapsed,

                "result":
                    result,
            }
        )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output_path = (
        output_dir
        / f"reasoning-knowledge-{timestamp}.json"
    )

    document = {
        "test":
            "HALON Knowledge -> Reasoning Integration",

        "retrievalPass":
            retrieval_pass,

        "retrievalTotal":
            len(
                QUESTIONS
            ),

        "completenessPass":
            completeness_pass,

        "completenessTotal":
            completeness_total,

        "results":
            results,
    }

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            document,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print(
        "============================================================"
    )
    print(
        " RESULT"
    )
    print(
        "============================================================"
    )
    print()
    print(
        "Knowledge retrieval: "
        f"{retrieval_pass}/{len(QUESTIONS)}"
    )

    print(
        "Enumeration completeness: "
        f"{completeness_pass}/{completeness_total}"
    )

    print()
    print(
        f"Full result: {output_path}"
    )
    print()

    if retrieval_pass != len(
        QUESTIONS
    ):

        return 1

    if (
        completeness_pass
        != completeness_total
    ):

        return 1

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
