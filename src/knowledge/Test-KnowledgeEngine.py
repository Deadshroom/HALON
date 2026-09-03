import argparse
import importlib.util
import json
import sys
import time

from datetime import datetime
from pathlib import Path
from typing import Any


# ============================================================
# HALON KNOWLEDGE ENGINE REGRESSION RUNNER
#
# Goals:
#   1. Load BGE exactly once for the entire regression run.
#   2. Do not rebuild evidence tables that are already complete.
#   3. Print only a compact summary to the terminal.
#   4. Save complete retrieval details to disk.
#
# This runner does NOT invoke Qwen or the HALON Reasoning Engine.
# ============================================================


REGRESSION_CASES = [
    {
        "name": "Historical user sessions",
        "query": "Who used this computer?",
        "expectedFamily": "windowsSessions",
    },
    {
        "name": "PowerShell process activity",
        "query": "What PowerShell activity occurred?",
        "expectedFamily": "processes",
    },
    {
        "name": "Windows errors",
        "query": "What errors occurred on this machine?",
        "expectedFamily": "windowsEvents",
    },
    {
        "name": "Identity activity",
        "query": "What identity activity occurred?",
        "expectedFamily": "identityEvents",
    },
    {
        "name": "Current sessions",
        "query": "What sessions were active when HALON collected evidence?",
        "expectedFamily": "currentSessions",
    },
    {
        "name": "Session lifecycle events",
        "query": "What Windows session events occurred?",
        "expectedFamily": "windowsSessionEvents",
    },
    {
        "name": "Windows services",
        "query": "What services were running or stopped?",
        "expectedFamily": "services",
    },
    {
        "name": "Interactive identity sessions",
        "query": (
            "What interactive security identity sessions "
            "were reconstructed?"
        ),
        "expectedFamily": "identitySessions",
    },
    {
        "name": "Host system information",
        "query": (
            "What hardware and Windows operating system "
            "is this machine running?"
        ),
        "expectedFamily": "system",
    },
    {
        "name": "Disk information",
        "query": "What disks and storage volumes are on this machine?",
        "expectedFamily": "disks",
    },
    {
        "name": "Event to process relationships",
        "query": (
            "Which historical processes did Windows events "
            "reference or correlate to?"
        ),
        "expectedFamily": "eventToProcess",
    },
    {
        "name": "Direct process parents",
        "query": (
            "What direct parent-child process relationships "
            "did HALON establish?"
        ),
        "expectedFamily": "processToParent",
    },
    {
        "name": "Process security logons",
        "query": (
            "Which Windows security logon identities were "
            "processes executed under?"
        ),
        "expectedFamily": "processToLogon",
    },
    {
        "name": "Process Windows sessions",
        "query": (
            "Which reconstructed Windows user sessions did "
            "processes occur within?"
        ),
        "expectedFamily": "processToWindowsSession",
    },
    {
        "name": "Evidence category summary",
        "query": (
            "What categories of evidence did HALON collect "
            "and how many records were in each category?"
        ),
        "expectedFamily": "evidenceSummary",
    },
    {
        "name": "Recurring event summary",
        "query": (
            "What recurring Windows event patterns did HALON "
            "observe by provider, event ID, level, and count?"
        ),
        "expectedFamily": "eventSummary",
    },
    {
        "name": "Process evidence capability",
        "query": (
            "Was Windows Process Creation auditing enabled and "
            "was historical Security Event 4688 evidence available?"
        ),
        "expectedFamily": "processEvidenceCapability",
    },
    {
        "name": "Reconstructed timeline",
        "query": "What happened in the reconstructed event timeline?",
        "expectedFamily": "timeline",
    },
    {
        "name": "Process lineage",
        "query": "What parent and ancestor process lineage was reconstructed?",
        "expectedFamily": "processLineages",
    },
    {
        "name": "Process execution context",
        "query": (
            "What process execution context and user session "
            "context was reconstructed?"
        ),
        "expectedFamily": "processExecutionContexts",
    },
    {
        "name": "Reconstructed incidents",
        "query": "What incidents were reconstructed by HALON?",
        "expectedFamily": "incidents",
    },
    {
        "name": "Incident context",
        "query": "What happened before and after the reconstructed incident?",
        "expectedFamily": "incidentContexts",
    },
    {
        "name": "Incident identities",
        "query": "Which identities or logon sessions overlapped an incident?",
        "expectedFamily": "incidentIdentities",
    },
    {
        "name": "Windows sessions at incident",
        "query": "Which Windows user sessions overlapped an incident?",
        "expectedFamily": "windowsSessionsAtIncident",
    },
]


def load_knowledge_engine_module(
    engine_path: Path,
):

    spec = importlib.util.spec_from_file_location(
        "halon_knowledge_engine",
        engine_path,
    )

    if spec is None or spec.loader is None:

        raise RuntimeError(
            f"Unable to load HALON Knowledge Engine: {engine_path}"
        )

    module = importlib.util.module_from_spec(
        spec
    )

    sys.modules[
        spec.name
    ] = module

    spec.loader.exec_module(
        module
    )

    return module


def get_table_row_count(
    table: Any,
) -> int:

    count_rows = getattr(
        table,
        "count_rows",
        None,
    )

    if callable(
        count_rows
    ):

        return int(
            count_rows()
        )

    # Compatibility fallback for LanceDB versions where
    # count_rows is unavailable.
    return len(
        table.to_arrow()
    )


def get_existing_family_count(
    engine: Any,
    table_name: str,
) -> int | None:

    try:

        table = engine.db.open_table(
            table_name
        )

    except Exception:

        return None

    try:

        return get_table_row_count(
            table
        )

    except Exception:

        return None


def rebuild_one_family(
    module: Any,
    engine: Any,
    family: str,
    records: list[dict[str, Any]],
) -> int:

    rows = module.build_family_rows(
        family=family,
        records=records,
    )

    if not rows:

        return 0

    search_texts = [
        row[
            "searchText"
        ]
        for row in rows
    ]

    vectors = (
        engine.embedding_model
        .encode(
            search_texts,
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
        ] = vector.tolist()

    engine.db.create_table(
        module.FAMILY_TABLES[
            family
        ],
        data=rows,
        mode="overwrite",
    )

    return len(
        rows
    )


def rebuild_one_metadata_table(
    module: Any,
    engine: Any,
    metadata_type: str,
    records: list[dict[str, Any]],
) -> int:

    rows = module.build_metadata_rows(
        metadata_type=
            metadata_type,

        records=
            records,
    )

    if not rows:

        return 0

    engine.db.create_table(
        module.METADATA_TABLES[
            metadata_type
        ],
        data=
            rows,
        mode=
            "overwrite",
    )

    return len(
        rows
    )


def prepare_database(
    module: Any,
    engine: Any,
    payload_path: Path,
    force_rebuild: bool,
) -> list[dict[str, Any]]:

    payload = module.load_payload(
        payload_path
    )

    family_records = (
        module.get_family_records(
            payload
        )
    )

    metadata_records = (
        module.get_metadata_records(
            payload
        )
    )

    preparation = []

    print()
    print(
        "Database preparation"
    )
    print(
        "------------------------------------------------------------"
    )

    for family in module.FAMILY_TABLES:

        records = family_records.get(
            family,
            [],
        )

        expected_count = len(
            records
        )

        table_name = (
            module.FAMILY_TABLES[
                family
            ]
        )

        existing_count = (
            get_existing_family_count(
                engine=engine,
                table_name=table_name,
            )
        )

        needs_rebuild = (
            force_rebuild
            or (
                expected_count > 0
                and existing_count != expected_count
            )
        )

        started = time.perf_counter()

        if needs_rebuild:

            actual_count = (
                rebuild_one_family(
                    module=module,
                    engine=engine,
                    family=family,
                    records=records,
                )
            )

            elapsed = (
                time.perf_counter()
                - started
            )

            action = "BUILT"

        else:

            actual_count = (
                existing_count
                if existing_count is not None
                else 0
            )

            elapsed = (
                time.perf_counter()
                - started
            )

            action = "OK"

        preparation.append(
            {
                "family":
                    family,

                "action":
                    action,

                "expectedCount":
                    expected_count,

                "actualCount":
                    actual_count,

                "elapsedSeconds":
                    elapsed,
            }
        )

        print(
            f"{action:<5} "
            f"{family:<28} "
            f"{actual_count:>6}/{expected_count:<6} "
            f"{elapsed:>7.2f}s"
        )

    print()
    print(
        "HALON metadata / provenance"
    )
    print(
        "------------------------------------------------------------"
    )

    for metadata_type in module.METADATA_TABLES:

        records = metadata_records.get(
            metadata_type,
            [],
        )

        expected_count = len(
            records
        )

        table_name = (
            module.METADATA_TABLES[
                metadata_type
            ]
        )

        existing_count = (
            get_existing_family_count(
                engine=engine,
                table_name=table_name,
            )
        )

        needs_rebuild = (
            force_rebuild
            or (
                expected_count > 0
                and existing_count != expected_count
            )
        )

        started = time.perf_counter()

        if needs_rebuild:

            actual_count = (
                rebuild_one_metadata_table(
                    module=module,
                    engine=engine,
                    metadata_type=
                        metadata_type,
                    records=
                        records,
                )
            )

            action = "BUILT"

        else:

            actual_count = (
                existing_count
                if existing_count is not None
                else 0
            )

            action = "OK"

        elapsed = (
            time.perf_counter()
            - started
        )

        preparation.append(
            {
                "family":
                    metadata_type,

                "action":
                    action,

                "expectedCount":
                    expected_count,

                "actualCount":
                    actual_count,

                "elapsedSeconds":
                    elapsed,
            }
        )

        print(
            f"{action:<5} "
            f"{metadata_type:<28} "
            f"{actual_count:>6}/{expected_count:<6} "
            f"{elapsed:>7.2f}s"
        )

    # Catalog is tiny. Rebuilding it every regression guarantees
    # that its cards match the current source code without paying
    # a meaningful runtime penalty.
    catalog_started = (
        time.perf_counter()
    )

    catalog_count = (
        engine.rebuild_family_catalog()
    )

    catalog_elapsed = (
        time.perf_counter()
        - catalog_started
    )

    print(
        f"BUILT {'familyCatalog':<28} "
        f"{catalog_count:>6}/{len(module.FAMILY_CATALOG):<6} "
        f"{catalog_elapsed:>7.2f}s"
    )

    preparation.append(
        {
            "family":
                "familyCatalog",

            "action":
                "BUILT",

            "expectedCount":
                len(
                    module.FAMILY_CATALOG
                ),

            "actualCount":
                catalog_count,

            "elapsedSeconds":
                catalog_elapsed,
        }
    )

    return preparation


def build_text_report(
    result_document: dict[str, Any],
) -> str:

    lines = []

    lines.append(
        "HALON Knowledge Engine Regression"
    )

    lines.append(
        "=" * 72
    )

    lines.append(
        f"Generated: {result_document['generatedAt']}"
    )

    lines.append(
        f"Payload: {result_document['payloadPath']}"
    )

    lines.append(
        f"Database: {result_document['databasePath']}"
    )

    lines.append(
        ""
    )

    lines.append(
        "DATABASE PREPARATION"
    )

    lines.append(
        "-" * 72
    )

    for item in result_document[
        "databasePreparation"
    ]:

        lines.append(
            (
                f"{item['action']:<5} "
                f"{item['family']:<28} "
                f"{item['actualCount']}/"
                f"{item['expectedCount']} "
                f"{item['elapsedSeconds']:.2f}s"
            )
        )

    lines.append(
        ""
    )

    lines.append(
        "REGRESSION RESULTS"
    )

    lines.append(
        "-" * 72
    )

    for case in result_document[
        "cases"
    ]:

        lines.append(
            ""
        )

        lines.append(
            (
                f"[{case['status']}] "
                f"{case['name']}"
            )
        )

        lines.append(
            f"Query: {case['query']}"
        )

        lines.append(
            (
                "Expected family: "
                f"{case['expectedFamily']}"
            )
        )

        lines.append(
            (
                "Selected families: "
                + ", ".join(
                    (
                        f"{entry['family']} "
                        f"({entry['distance']:.6f})"
                    )
                    for entry in case[
                        "catalogResults"
                    ]
                )
            )
        )

        lines.append(
            (
                f"Elapsed: "
                f"{case['elapsedSeconds']:.2f}s"
            )
        )

        lines.append(
            ""
        )

        for family, records in case[
            "familyResults"
        ].items():

            lines.append(
                f"FAMILY: {family}"
            )

            for index, record in enumerate(
                records,
                start=1,
            ):

                lines.append(
                    f"  Result {index}"
                )

                lines.append(
                    (
                        "  Distance: "
                        f"{record.get('distance')}"
                    )
                )

                lines.append(
                    (
                        "  Metadata: "
                        + json.dumps(
                            record.get(
                                "metadata",
                                {},
                            ),
                            ensure_ascii=False,
                        )
                    )
                )

                lines.append(
                    (
                        "  SearchText: "
                        + str(
                            record.get(
                                "searchText",
                                "",
                            )
                        )
                    )
                )

                lines.append(
                    (
                        "  OriginalRecord: "
                        + json.dumps(
                            record.get(
                                "record",
                                {},
                            ),
                            ensure_ascii=False,
                        )
                    )
                )

    lines.append(
        ""
    )

    lines.append(
        "SUMMARY"
    )

    lines.append(
        "-" * 72
    )

    summary = result_document[
        "summary"
    ]

    lines.append(
        f"PASS: {summary['pass']}"
    )

    lines.append(
        f"WARN: {summary['warn']}"
    )

    lines.append(
        f"TOTAL: {summary['total']}"
    )

    lines.append(
        (
            "Total elapsed: "
            f"{summary['elapsedSeconds']:.2f}s"
        )
    )

    return "\n".join(
        lines
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "HALON Knowledge Engine "
            "regression runner."
        )
    )

    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "HALON repository root. Defaults to two "
            "levels above this script."
        ),
    )

    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help=(
            "Re-embed every evidence family even when "
            "the existing LanceDB row count is correct."
        ),
    )

    parser.add_argument(
        "--family-limit",
        type=int,
        default=2,
    )

    parser.add_argument(
        "--per-family-limit",
        type=int,
        default=3,
    )

    args = parser.parse_args()

    script_path = Path(
        __file__
    ).resolve()

    if args.repo_root is None:

        # Expected placement:
        #   C:\Dev\halon\src\knowledge\Test-KnowledgeEngine.py
        repo_root = (
            script_path
            .parents[
                2
            ]
        )

    else:

        repo_root = (
            args.repo_root
            .resolve()
        )

    engine_path = (
        repo_root
        / "src"
        / "knowledge"
        / "Halon.KnowledgeEngine.py"
    )

    payload_path = (
        repo_root
        / "output"
        / "WADESYSTEM_20260829_140700"
        / "evidence-payload-v1.json"
    )

    database_path = (
        repo_root
        / "data"
        / "knowledge"
    )

    output_directory = (
        repo_root
        / "output"
        / "regression"
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not engine_path.exists():

        raise FileNotFoundError(
            f"Knowledge Engine not found: {engine_path}"
        )

    if not payload_path.exists():

        raise FileNotFoundError(
            f"Evidence payload not found: {payload_path}"
        )

    total_started = (
        time.perf_counter()
    )

    print()
    print(
        "============================================================"
    )

    print(
        " HALON Knowledge Engine Regression"
    )

    print(
        "============================================================"
    )

    print(
        "Loading HALON Knowledge Engine and BGE once..."
    )

    module = (
        load_knowledge_engine_module(
            engine_path
        )
    )

    engine = (
        module.HalonKnowledgeEngine(
            database_path=
                database_path,
        )
    )

    print(
        "BGE ready."
    )

    preparation = (
        prepare_database(
            module=module,
            engine=engine,
            payload_path=payload_path,
            force_rebuild=
                args.force_rebuild,
        )
    )

    print()
    print(
        "Regression queries"
    )

    print(
        "------------------------------------------------------------"
    )

    cases = []

    pass_count = 0
    warn_count = 0

    for index, case in enumerate(
        REGRESSION_CASES,
        start=1,
    ):

        started = (
            time.perf_counter()
        )

        (
            catalog_results,
            family_results,
        ) = (
            engine.search_with_family_catalog(
                query=
                    case[
                        "query"
                    ],

                family_limit=
                    args.family_limit,

                per_family_limit=
                    args.per_family_limit,
            )
        )

        elapsed = (
            time.perf_counter()
            - started
        )

        selected_families = [
            result[
                "family"
            ]
            for result in catalog_results
        ]

        if (
            case[
                "expectedFamily"
            ]
            in selected_families
        ):

            status = "PASS"
            pass_count += 1

        else:

            status = "WARN"
            warn_count += 1

        catalog_display = ", ".join(
            (
                f"{result['family']} "
                f"({result['distance']:.4f})"
            )
            for result in catalog_results
        )

        print(
            (
                f"[{status}] "
                f"{index:02d}/{len(REGRESSION_CASES):02d} "
                f"{case['name']:<30} "
                f"{elapsed:>6.2f}s"
            )
        )

        print(
            (
                f"       expected={case['expectedFamily']} "
                f"| selected={catalog_display}"
            )
        )

        cases.append(
            {
                "name":
                    case[
                        "name"
                    ],

                "query":
                    case[
                        "query"
                    ],

                "expectedFamily":
                    case[
                        "expectedFamily"
                    ],

                "status":
                    status,

                "elapsedSeconds":
                    elapsed,

                "catalogResults":
                    catalog_results,

                "familyResults":
                    family_results,
            }
        )

    total_elapsed = (
        time.perf_counter()
        - total_started
    )

    generated_at = (
        datetime.now()
        .astimezone()
        .isoformat(
            timespec="seconds"
        )
    )

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S"
        )
    )

    json_path = (
        output_directory
        / (
            "knowledge-"
            f"{timestamp}.json"
        )
    )

    text_path = (
        output_directory
        / (
            "knowledge-"
            f"{timestamp}.txt"
        )
    )

    result_document = {
        "generatedAt":
            generated_at,

        "enginePath":
            str(
                engine_path
            ),

        "payloadPath":
            str(
                payload_path
            ),

        "databasePath":
            str(
                database_path
            ),

        "familyLimit":
            args.family_limit,

        "perFamilyLimit":
            args.per_family_limit,

        "forceRebuild":
            args.force_rebuild,

        "databasePreparation":
            preparation,

        "cases":
            cases,

        "summary": {
            "pass":
                pass_count,

            "warn":
                warn_count,

            "total":
                len(
                    REGRESSION_CASES
                ),

            "elapsedSeconds":
                total_elapsed,
        },
    }

    json_path.write_text(
        json.dumps(
            result_document,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    text_path.write_text(
        build_text_report(
            result_document
        ),
        encoding="utf-8",
    )

    print()
    print(
        "============================================================"
    )

    print(
        " Regression complete"
    )

    print(
        "============================================================"
    )

    print(
        (
            f"PASS: {pass_count}  "
            f"WARN: {warn_count}  "
            f"TOTAL: {len(REGRESSION_CASES)}"
        )
    )

    print(
        f"Elapsed: {total_elapsed:.2f}s"
    )

    print(
        f"Full JSON: {json_path}"
    )

    print(
        f"Full text: {text_path}"
    )

    print()

    # WARN means semantic-family selection needs review,
    # not that the runner itself failed.
    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )

