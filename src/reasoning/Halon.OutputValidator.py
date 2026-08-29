from typing import Any


# ============================================================
# HALON REASONING OUTPUT VALIDATOR
#
# Deterministically validates the structural contract of a
# Reasoning Engine response.
#
# This validator:
#   - does NOT modify model output
#   - does NOT interpret evidence
#   - does NOT determine whether reasoning is correct
#   - does NOT call the model
#
# It validates whether the model followed HALON's required
# response structure.
# ============================================================


REQUIRED_SECTIONS = [
    "RECONSTRUCTED EVIDENCE",
    "HYPOTHESES",
    "KNOWLEDGE REQUIRED",
    "LIMITATIONS",
]


HYPOTHESIS_FALLBACK = (
    "The available evidence does not presently support a more "
    "specific failure hypothesis."
)


def normalize_lines(
    answer: str
) -> list[str]:

    return [
        line.strip()
        for line in answer.splitlines()
    ]


def find_section_occurrences(
    lines: list[str]
) -> dict[str, list[int]]:

    occurrences = {
        section: []
        for section in REQUIRED_SECTIONS
    }

    for index, line in enumerate(
        lines
    ):

        if line in occurrences:

            occurrences[line].append(
                index
            )

    return occurrences


def extract_sections(
    lines: list[str],
    occurrences: dict[str, list[int]]
) -> dict[str, str]:

    sections = {}

    first_positions = []

    for section in REQUIRED_SECTIONS:

        positions = occurrences.get(
            section,
            []
        )

        if positions:

            first_positions.append(
                (
                    positions[0],
                    section,
                )
            )

    first_positions.sort(
        key=lambda item:
            item[0]
    )

    for index, (
        start_position,
        section
    ) in enumerate(
        first_positions
    ):

        if (
            index + 1
            < len(first_positions)
        ):

            end_position = (
                first_positions[
                    index + 1
                ][0]
            )

        else:

            end_position = len(
                lines
            )

        content_lines = lines[
            start_position + 1:
            end_position
        ]

        content = "\n".join(
            content_lines
        ).strip()

        sections[
            section
        ] = content

    return sections


def validate_reasoning_output(
    answer: str
) -> dict[str, Any]:

    violations = []

    if not isinstance(
        answer,
        str
    ):

        return {
            "isValid": False,
            "violations": [
                {
                    "code":
                        "InvalidOutputType",

                    "message":
                        "Reasoning output must be a string.",
                }
            ],
            "expectedSections":
                REQUIRED_SECTIONS,
            "observedSections":
                [],
            "sections":
                {},
        }

    if not answer.strip():

        return {
            "isValid": False,
            "violations": [
                {
                    "code":
                        "EmptyOutput",

                    "message":
                        "Reasoning output was empty.",
                }
            ],
            "expectedSections":
                REQUIRED_SECTIONS,
            "observedSections":
                [],
            "sections":
                {},
        }

    lines = normalize_lines(
        answer
    )

    occurrences = (
        find_section_occurrences(
            lines
        )
    )

    # --------------------------------------------------------
    # REQUIRED SECTION PRESENCE
    # --------------------------------------------------------

    for section in REQUIRED_SECTIONS:

        count = len(
            occurrences[
                section
            ]
        )

        if count == 0:

            violations.append(
                {
                    "code":
                        "MissingSection",

                    "section":
                        section,

                    "message":
                        (
                            "Required section "
                            f"'{section}' is missing."
                        ),
                }
            )

        elif count > 1:

            violations.append(
                {
                    "code":
                        "DuplicateSection",

                    "section":
                        section,

                    "count":
                        count,

                    "message":
                        (
                            "Required section "
                            f"'{section}' appears "
                            f"{count} times."
                        ),
                }
            )

    # --------------------------------------------------------
    # OBSERVED SECTION ORDER
    # --------------------------------------------------------

    observed_sections = []

    observed_positions = []

    for section in REQUIRED_SECTIONS:

        positions = occurrences[
            section
        ]

        if positions:

            observed_positions.append(
                (
                    positions[0],
                    section,
                )
            )

    observed_positions.sort(
        key=lambda item:
            item[0]
    )

    observed_sections = [
        section
        for _, section
        in observed_positions
    ]

    expected_present_order = [
        section
        for section in REQUIRED_SECTIONS
        if occurrences[
            section
        ]
    ]

    if (
        observed_sections
        != expected_present_order
    ):

        violations.append(
            {
                "code":
                    "SectionOrderViolation",

                "expected":
                    REQUIRED_SECTIONS,

                "observed":
                    observed_sections,

                "message":
                    (
                        "Reasoning sections were not "
                        "returned in the required order."
                    ),
            }
        )

    # --------------------------------------------------------
    # EXTRACT SECTION CONTENT
    # --------------------------------------------------------

    sections = extract_sections(
        lines,
        occurrences,
    )

    # --------------------------------------------------------
    # EMPTY SECTIONS
    # --------------------------------------------------------

    for section in REQUIRED_SECTIONS:

        if section not in sections:
            continue

        if not sections[
            section
        ].strip():

            violations.append(
                {
                    "code":
                        "EmptySection",

                    "section":
                        section,

                    "message":
                        (
                            "Required section "
                            f"'{section}' is empty."
                        ),
                }
            )

    # --------------------------------------------------------
    # HYPOTHESIS FALLBACK PLACEMENT
    # --------------------------------------------------------

    fallback_locations = []

    for section, content in (
        sections.items()
    ):

        if HYPOTHESIS_FALLBACK in (
            " ".join(
                content.split()
            )
        ):

            fallback_locations.append(
                section
            )

    if fallback_locations:

        invalid_locations = [
            section
            for section
            in fallback_locations
            if section
            != "HYPOTHESES"
        ]

        if invalid_locations:

            violations.append(
                {
                    "code":
                        "HypothesisFallbackMisplaced",

                    "expectedSection":
                        "HYPOTHESES",

                    "observedSections":
                        fallback_locations,

                    "message":
                        (
                            "The no-specific-hypothesis "
                            "fallback statement may appear "
                            "only under HYPOTHESES."
                        ),
                }
            )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {
        "isValid":
            len(violations) == 0,

        "violations":
            violations,

        "expectedSections":
            REQUIRED_SECTIONS,

        "observedSections":
            observed_sections,

        "sections":
            sections,
    }