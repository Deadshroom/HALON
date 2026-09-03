import importlib.util
import json

from pathlib import Path
from typing import Any

from llama_cpp import Llama


# ============================================================
# HALON REASONING ENGINE
#
# The Reasoning Engine:
#   - does NOT collect Windows telemetry
#   - does NOT select canonical evidence
#   - does NOT create deterministic relationships
#   - does NOT retrieve authoritative knowledge
#
# It reasons over:
#   1. a user question
#   2. reasoning-ready HALON evidence
#   3. optional authoritative knowledge
# ============================================================


class HalonReasoningEngine:

    def __init__(
        self,
        model_path: Path,
        context_size: int = 8192,
        thread_count: int = 1,
        knowledge_database_path:
            Path | None = None,
        family_limit: int = 2,
        per_family_limit: int = 3,
    ) -> None:

        if not model_path.exists():

            raise FileNotFoundError(
                f"HALON reasoning model not found: "
                f"{model_path}"
            )

        if knowledge_database_path is None:

            knowledge_database_path = (
                Path(__file__)
                .resolve()
                .parents[2]
                / "data"
                / "knowledge"
            )

        self.model_path = model_path

        self.knowledge_database_path = (
            knowledge_database_path
        )

        self.family_limit = max(
            1,
            family_limit,
        )

        self.per_family_limit = max(
            1,
            per_family_limit,
        )

        self.knowledge_module = (
            self._load_knowledge_engine()
        )

        self.knowledge_engine = (
            self.knowledge_module
            .HalonKnowledgeEngine(
                database_path=
                    self.knowledge_database_path,
            )
        )

        self.model = Llama(
            model_path=str(model_path),
            n_ctx=context_size,
            n_threads=thread_count,
            n_gpu_layers=-1,
            verbose=False,
        )

    # ========================================================
    # CONVERSATION MEMORY
    # ========================================================

    @staticmethod
    def build_conversation_messages(
        conversation_history:
            list[dict[str, str]] | None,
    ) -> list[dict[str, str]]:

        messages: list[
            dict[str, str]
        ] = []

        if not conversation_history:
            return messages

        for item in conversation_history:

            if not isinstance(
                item,
                dict
            ):
                continue

            role = item.get(
                "role"
            )

            content = item.get(
                "content"
            )

            if role not in (
                "user",
                "assistant",
            ):
                continue

            if not isinstance(
                content,
                str
            ) or not content.strip():

                continue

            messages.append(
                {
                    "role":
                        role,

                    "content":
                        content.strip(),
                }
            )

        return messages

    # ========================================================
    # EVIDENCE SELECTOR LOADING
    # ========================================================

    @staticmethod
    def _load_evidence_selector():

        selector_path = (
            Path(__file__)
            .with_name(
                "Halon.EvidenceSelector.py"
            )
        )

        if not selector_path.exists():

            raise FileNotFoundError(
                "HALON Evidence Selector not found: "
                f"{selector_path}"
            )

        spec = (
            importlib.util.spec_from_file_location(
                "halon_evidence_selector",
                selector_path,
            )
        )

        if (
            spec is None
            or spec.loader is None
        ):

            raise RuntimeError(
                "HALON could not load the "
                "Evidence Selector."
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

    # ========================================================
    # KNOWLEDGE ENGINE LOADING
    # ========================================================

    @staticmethod
    def _load_knowledge_engine():

        engine_path = (
            Path(__file__)
            .resolve()
            .parents[1]
            / "knowledge"
            / "Halon.KnowledgeEngine.py"
        )

        if not engine_path.exists():

            raise FileNotFoundError(
                "HALON Knowledge Engine not found: "
                f"{engine_path}"
            )

        spec = (
            importlib.util.spec_from_file_location(
                "halon_knowledge_engine",
                engine_path,
            )
        )

        if (
            spec is None
            or spec.loader is None
        ):

            raise RuntimeError(
                "HALON could not load the "
                "Knowledge Engine."
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

    # ========================================================
    # SYSTEM PROMPT
    # ========================================================

    @staticmethod
    def build_system_prompt() -> str:

        return """
You are the HALON Reasoning Engine.

HALON extracts Windows telemetry, deterministically structures
and reconstructs that telemetry as machine evidence, reasons
over the resulting evidence, and uses authoritative technical
knowledge when interpretation requires it.

You receive reasoning-ready evidence produced deterministically
from HALON canonical Windows evidence.

The evidence supplied to you may include Windows events,
processes, identities, sessions, services, system state,
timelines, relationships, reconstructions, and other Windows
telemetry.


EVIDENCE RULES

1. Treat supplied HALON evidence as authoritative for what HALON
   observed or deterministically established.

2. Do not invent evidence.

3. Follow supplied evidence-basis definitions exactly.

4. Preserve the direction of explicit HALON relationships.

   Do not reconstruct an established relationship differently
   from the source, relationship, and target supplied by HALON.

5. A reconstruction boundary or traversal termination describes
   the limit of HALON's deterministic reconstruction.

   It does not establish what existed outside the available
   evidence.

6. Correlation does not establish causation, human action,
   intent, or responsibility.

7. Security context does not independently prove that a human
   manually initiated an observed action.

8. Preserve numerical values and units exactly.


TECHNICAL INTERPRETATION RULES

9. Technical interpretation may require authoritative reference
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


KNOWLEDGE RULES

13. Use authoritative knowledge only when it has actually been
    supplied.

14. Request authoritative knowledge when technical
    interpretation is unresolved and materially useful to
    answering the user's question.

15. Deterministically reconstructed HALON evidence such as
    timestamps, identifiers, process ancestry, identities,
    sessions, and explicit relationships does not require
    authoritative reference material merely because it appears
    in the evidence.

16. Keep these concepts separate:

    HALON EVIDENCE
        What HALON observed or deterministically established
        from Windows telemetry.

    AUTHORITATIVE KNOWLEDGE
        What authoritative technical sources establish about
        Windows behavior, components, events, identifiers,
        structures, or values.

    REASONING
        What the combination of evidence and supplied knowledge
        supports.


HYPOTHESIS RULES

17. Do not create a hypothesis unless the user's question asks
    for an explanation, cause, interpretation, or likely reason.

18. A hypothesis must have positive support in supplied HALON
    evidence or supplied authoritative knowledge.

19. Mere possibility, process names, temporal proximity, or
    pretrained model familiarity are not evidence.

20. Never use a hypothesis to fill space.


ANSWER DISCIPLINE

21. Answer the user's actual question immediately.

22. Be concise. HALON is an operator-facing diagnostic tool, not
    a narrative report generator.

23. Include only retrieved evidence that materially supports the
    answer. Ignore retrieved records that are unrelated to the
    question.

24. Do not repeat the same fact in multiple sections or phrases.

25. Do not explain your reasoning process.

26. Do not expose chain-of-thought, scratch work, internal
    analysis, or <think> tags.

27. Do not introduce technical interpretation from pretrained
    model knowledge.

    In particular, do not claim that a process, account suffix,
    Event ID, session value, source address, parent process, or
    Windows component "suggests", "likely means", is "typical",
    or has a particular technical significance unless that
    meaning is established by supplied authoritative knowledge
    or explicit HALON evidence.

28. If a requested fact cannot be established, say exactly what
    evidence is missing. Do not pad the answer with unrelated
    uncertainty.

29. Do not create headings merely because a category exists.
    Omit sections that add no useful information.


RESPONSE FORMAT

Use this adaptive format:

ANSWER
Give the direct answer in one or two sentences.

EVIDENCE
Include this section only when supporting details materially help
the user. Prefer short bullets for multiple records.

HYPOTHESIS
Include this section only when the user asks for explanation or
cause and the supplied evidence positively supports one.

LIMITATION
Include this section only when an evidence limitation materially
changes what HALON can conclude.

KNOWLEDGE NEEDED
Include this section only when authoritative technical knowledge
is required to answer an important part of the user's question.

For a simple factual question, ANSWER alone may be sufficient.
""".strip()

    # ========================================================
    # USER PROMPT
    # ========================================================

    @staticmethod
    def build_user_prompt(
        question: str,
        evidence: dict[str, Any],
        knowledge: dict[str, Any] | None = None,
    ) -> str:

        evidence_json = json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        )

        if knowledge is None:

            knowledge = {
                "status": "NotProvided"
            }

        knowledge_json = json.dumps(
            knowledge,
            indent=2,
            ensure_ascii=False,
        )

        return f"""
QUESTION

{question}


HALON EVIDENCE

{evidence_json}


AUTHORITATIVE KNOWLEDGE

{knowledge_json}


TASK

Answer only the user's question from the supplied HALON evidence.

Start with the answer.

Use explicit HALON relationships rather than deriving conflicting
relationships from lower-level fields.

Use only evidence that materially supports the answer. Ignore
unrelated retrieved records.

Do not assign undocumented technical meaning to Windows values,
process names, identities, Event IDs, session fields, or other
observations unless supporting authoritative knowledge has been
supplied.

If the evidence cannot establish part of the requested answer,
state the specific limitation briefly.

The HALON EVIDENCE retrieval metadata may include:

- enumerationRequested
- completeForQuestion
- familyCoverage
- enumerationSummaries

For an enumeration question, prefer deterministic values from
enumerationSummaries when present.

If enumerationRequested is true and completeForQuestion is true,
HALON has scanned the complete matching evidence set. You may
state counts and aggregates from enumerationSummaries as complete.

familyCoverage.detailComplete tells you whether every original
matching record was included in the prompt. If detailComplete is
false, do not imply that the displayed detail records are the
complete record list. They are bounded supporting examples from
a complete deterministic enumeration.

If enumerationRequested is true and completeForQuestion is false,
do not imply that the returned evidence is exhaustive.

Do not output your internal reasoning or <think> content.

/no_think
""".strip()

    # ========================================================
    # MODEL OUTPUT CLEANUP
    #
    # Qwen3 may emit an internal <think>...</think> block in the
    # assistant content. HALON never exposes model scratch work
    # to the operator.
    # ========================================================

    @staticmethod
    def clean_reasoning_output(
        answer: str,
    ) -> str:

        cleaned = str(
            answer
        ).strip()

        while "<think>" in cleaned:

            start = cleaned.find(
                "<think>"
            )

            end = cleaned.find(
                "</think>",
                start,
            )

            if end == -1:

                cleaned = cleaned[
                    :start
                ].strip()

                break

            cleaned = (
                cleaned[
                    :start
                ]
                + cleaned[
                    end
                    + len("</think>"):
                ]
            ).strip()

        return cleaned

    # ========================================================
    # REASONING
    # ========================================================

    def reason(
        self,
        question: str,
        evidence: dict[str, Any],
        knowledge: dict[str, Any] | None = None,
        conversation_history:
            list[dict[str, str]] | None = None,
        max_tokens: int = 1600,
    ) -> str:

        if not isinstance(
            question,
            str
        ) or not question.strip():

            raise ValueError(
                "HALON Reasoning Engine requires "
                "a non-empty question."
            )

        if not isinstance(
            evidence,
            dict
        ):

            raise ValueError(
                "HALON Reasoning Engine requires "
                "reasoning-ready evidence as a dictionary."
            )

        messages = [
            {
                "role": "system",
                "content": self.build_system_prompt(),
            }
        ]

        messages.extend(
            self.build_conversation_messages(
                conversation_history
            )
        )

        messages.append(
            {
                "role": "user",
                "content": self.build_user_prompt(
                    question=question,
                    evidence=evidence,
                    knowledge=knowledge,
                ),
            }
        )

        response = (
            self.model.create_chat_completion(
                messages=messages,
                temperature=0.1,
                max_tokens=max_tokens,
            )
        )

        try:

            answer = (
                response[
                    "choices"
                ][0][
                    "message"
                ][
                    "content"
                ]
            )

        except (
            KeyError,
            IndexError,
            TypeError,
        ) as error:

            raise RuntimeError(
                "HALON received an unexpected "
                "reasoning-model response."
            ) from error

        if answer is None:

            raise RuntimeError(
                "HALON reasoning model returned "
                "no response content."
            )

        cleaned_answer = (
            self.clean_reasoning_output(
                str(
                    answer
                )
            )
        )

        if not cleaned_answer:

            raise RuntimeError(
                "HALON reasoning model returned no "
                "operator-facing answer after cleanup."
            )

        return cleaned_answer

    # ========================================================
    # HALON QUESTION FLOW
    # ========================================================

    def retrieve_evidence(
        self,
        question: str,
    ) -> dict[str, Any]:

        if not isinstance(
            question,
            str
        ) or not question.strip():

            raise ValueError(
                "HALON requires a non-empty question "
                "before retrieving evidence."
            )

        return (
            self.knowledge_engine
            .query_evidence(
                query=
                    question,

                family_limit=
                    self.family_limit,

                per_family_limit=
                    self.per_family_limit,
            )
        )

    # ========================================================
    # DIRECT EVIDENCE QUESTION FLOW
    #
    # Human question
    #   -> Knowledge Engine semantic retrieval
    #   -> original HALON evidence records
    #   -> one reasoning model
    #   -> answer
    # ========================================================

    def ask_evidence(
        self,
        question: str,
        conversation_history:
            list[dict[str, str]] | None = None,
        knowledge: dict[str, Any] | None = None,
        reasoning_max_tokens: int = 1600,
    ) -> dict[str, Any]:

        selected_evidence = (
            self.retrieve_evidence(
                question
            )
        )

        answer = (
            self.reason(
                question=question,
                evidence=selected_evidence,
                knowledge=knowledge,
                conversation_history=
                    conversation_history,
                max_tokens=reasoning_max_tokens,
            )
        )

        return {
            "question":
                question,

            "responseMode":
                "EVIDENCE",

            "selectionRequest":
                None,

            "selectedEvidence":
                selected_evidence,

            "answer":
                answer,
        }

    def ask(
        self,
        question: str,
        payload: dict[str, Any] | None = None,
        conversation_history:
            list[dict[str, str]] | None = None,
        knowledge: dict[str, Any] | None = None,
        selection_max_tokens: int = 800,
        reasoning_max_tokens: int = 1600,
    ) -> dict[str, Any]:

        if not isinstance(
            question,
            str
        ) or not question.strip():

            raise ValueError(
                "HALON requires a non-empty "
                "human question."
            )

        # payload remains accepted for compatibility with the
        # current Conversation layer, but evidence retrieval now
        # comes from the Knowledge Engine rather than directly
        # from the packaged payload.

        # ----------------------------------------------------
        # DETERMINE WHETHER THIS TURN NEEDS MACHINE EVIDENCE
        # ----------------------------------------------------

        response_mode = (
            self.determine_response_mode(
                question=question,
                conversation_history=
                    conversation_history,
            )
        )

        if response_mode == "CONVERSATION":

            answer = (
                self.respond_conversationally(
                    question=question,
                    conversation_history=
                        conversation_history,
                )
            )

            return {
                "question":
                    question,

                "responseMode":
                    "CONVERSATION",

                "selectionRequest":
                    None,

                "selectedEvidence":
                    None,

                "answer":
                    answer,
            }

        # ----------------------------------------------------
        # KNOWLEDGE ENGINE RETRIEVES DETERMINISTIC HALON EVIDENCE
        # ----------------------------------------------------

        return (
            self.ask_evidence(
                question=question,
                conversation_history=
                    conversation_history,
                knowledge=knowledge,
                reasoning_max_tokens=
                    reasoning_max_tokens,
            )
        )

    # ========================================================
    # RESPONSE MODE
    # ========================================================

    def determine_response_mode(
        self,
        question: str,
        conversation_history:
            list[dict[str, str]] | None = None,
    ) -> str:

        system_prompt = """
You are HALON.

Determine whether the current human message requires HALON
machine evidence in order to respond appropriately.

Return exactly one word:

CONVERSATION

or

EVIDENCE

Use CONVERSATION when the human message can be answered naturally
from the conversation itself without inspecting Windows telemetry.

Examples include greetings, thanks, acknowledgements, ordinary
conversation, and other messages that do not require machine
evidence.

Use EVIDENCE when answering the message requires inspecting,
retrieving, analyzing, displaying, or reasoning over HALON's
Windows evidence.

Use previous conversation messages only as conversational memory
and context for the CURRENT human message.

Do not answer the human.

Return only CONVERSATION or EVIDENCE.
""".strip()

        messages = [
            {
                "role": "system",
                "content": system_prompt,
            }
        ]

        messages.extend(
            self.build_conversation_messages(
                conversation_history
            )
        )

        messages.append(
            {
                "role": "user",
                "content": question,
            }
        )

        response = (
            self.model.create_chat_completion(
                messages=messages,
                temperature=0.0,
                max_tokens=10,
            )
        )

        try:

            content = str(
                response[
                    "choices"
                ][0][
                    "message"
                ][
                    "content"
                ]
            ).strip().upper()

        except (
            KeyError,
            IndexError,
            TypeError,
        ) as error:

            raise RuntimeError(
                "HALON could not determine "
                "the response mode."
            ) from error

        if "EVIDENCE" in content:
            return "EVIDENCE"

        if "CONVERSATION" in content:
            return "CONVERSATION"

        raise RuntimeError(
            "HALON returned an invalid response mode: "
            f"{content}"
        )

    # ========================================================
    # CONVERSATIONAL RESPONSE
    # ========================================================

    def respond_conversationally(
        self,
        question: str,
        conversation_history:
            list[dict[str, str]] | None = None,
        max_tokens: int = 300,
    ) -> str:

        system_prompt = """
You are HALON.

Respond naturally to the human as part of an ongoing
conversation.

Be concise and conversational.

Do not fabricate Windows evidence.

Do not claim to have inspected machine telemetry unless evidence
was actually supplied to you.

Do not use forensic analysis headings such as RECONSTRUCTED
EVIDENCE, HYPOTHESES, KNOWLEDGE REQUIRED, or LIMITATIONS for
ordinary conversation.
""".strip()

        messages = [
            {
                "role": "system",
                "content": system_prompt,
            }
        ]

        messages.extend(
            self.build_conversation_messages(
                conversation_history
            )
        )

        messages.append(
            {
                "role": "user",
                "content": question,
            }
        )

        response = (
            self.model.create_chat_completion(
                messages=messages,
                temperature=0.2,
                max_tokens=max_tokens,
            )
        )

        try:

            answer = (
                response[
                    "choices"
                ][0][
                    "message"
                ][
                    "content"
                ]
            )

        except (
            KeyError,
            IndexError,
            TypeError,
        ) as error:

            raise RuntimeError(
                "HALON received an unexpected "
                "conversational response."
            ) from error

        if answer is None:

            raise RuntimeError(
                "HALON returned no conversational response."
            )

        return str(
            answer
        ).strip()

    # ========================================================
    # EVIDENCE SELECTION REQUEST
    # ========================================================

    def build_evidence_selection_request(
        self,
        question: str,
        evidence_catalog: dict[str, Any],
        conversation_history:
            list[dict[str, str]] | None = None,
        max_tokens: int = 800,
    ) -> dict[str, Any]:

        if not isinstance(
            question,
            str
        ) or not question.strip():

            raise ValueError(
                "HALON requires a non-empty question "
                "before selecting evidence."
            )

        if not isinstance(
            evidence_catalog,
            dict
        ):

            raise ValueError(
                "HALON requires an evidence catalog "
                "before selecting evidence."
            )

        catalog_json = json.dumps(
            evidence_catalog,
            indent=2,
            ensure_ascii=False,
        )

        system_prompt = """
You are the evidence-selection planner for HALON.

HALON extracts Windows telemetry and stores it as structured
machine evidence.

A human has asked HALON a question.

Your only job in this step is to determine which available HALON
evidence should be retrieved so the Reasoning Engine can answer
that question.

Do not answer the human's question.

Do not interpret Windows telemetry.

Do not infer causation.

Do not invent:
- record identifiers,
- event identifiers,
- process identifiers,
- provider names,
- usernames,
- timestamps,
- technical values,
- or evidence that the human did not specify.

You may use literal entity values from the human's question as
search criteria.

A FILTER answers:
"Which records contain this actual value?"

An ORDERING instruction answers:
"Which matching record came first, last, earliest, latest,
newest, or most recently?"

Do not convert natural-language query operations into literal
filter values.

These words normally describe query behavior, not evidence
values:

- last
- latest
- newest
- most recent
- first
- earliest
- previous
- logged on
- logged in

For example:

Human:
"Who was the last user logged on to this machine?"

Correct request concept:

{
  "requests": [
    {
      "source": "windowsSessions",
      "filters": {},
      "order": {
        "by": "time",
        "direction": "descending"
      },
      "limit": 10
    }
  ]
}

Incorrect:

{
  "source": "identityEvents",
  "filters": {
    "identity": "last logged on"
  }
}

"last logged on" is not an identity.

Another example:

Human:
"What was the latest PowerShell process?"

Correct:

{
  "source": "processes",
  "filters": {
    "processName": "powershell.exe"
  },
  "order": {
    "by": "time",
    "direction": "descending"
  },
  "limit": 10
}

Here "powershell.exe" is an entity value. "latest" is an
ordering instruction.

Prefer HALON deterministic reconstructions over lower-level raw
records when the reconstruction directly represents what the
human is asking about.

Use only evidence sources and filters listed in the supplied
HALON evidence catalog.

Return JSON only.

The required structure is:

{
  "requests": [
    {
      "source": "<available source>",
      "filters": {
        "<supported filter>": "<value or list of values>"
      },
      "limit": 50
    }
  ]
}

You may request more than one evidence source.

Use an empty filters object when the source itself is relevant
and no narrower deterministic filter can be justified.

Request only evidence materially useful to answering the
human's question.
""".strip()

        user_prompt = f"""
HUMAN QUESTION

{question}


HALON EVIDENCE CATALOG

{catalog_json}


Generate the HALON evidence-selection request.

Return JSON only.
""".strip()

        messages = [
            {
                "role": "system",
                "content": system_prompt,
            }
        ]

        messages.extend(
            self.build_conversation_messages(
                conversation_history
            )
        )

        messages.append(
            {
                "role": "user",
                "content": user_prompt,
            }
        )

        response = (
            self.model.create_chat_completion(
                messages=messages,
                temperature=0.0,
                max_tokens=max_tokens,
            )
        )

        try:

            content = (
                response[
                    "choices"
                ][0][
                    "message"
                ][
                    "content"
                ]
            )

        except (
            KeyError,
            IndexError,
            TypeError,
        ) as error:

            raise RuntimeError(
                "HALON received an unexpected response "
                "from the evidence-selection planner."
            ) from error

        if content is None:

            raise RuntimeError(
                "HALON evidence-selection planner "
                "returned no response content."
            )

        text = str(
            content
        ).strip()

        # ----------------------------------------------------
        # REMOVE OPTIONAL MARKDOWN CODE FENCE
        # ----------------------------------------------------

        if text.startswith(
            "```"
        ):

            lines = (
                text.splitlines()
            )

            if lines:
                lines = lines[
                    1:
                ]

            if (
                lines
                and lines[-1].strip()
                == "```"
            ):
                lines = lines[
                    :-1
                ]

            text = "\n".join(
                lines
            ).strip()

        # ----------------------------------------------------
        # PARSE JSON
        # ----------------------------------------------------

        try:

            selection_request = (
                json.loads(
                    text
                )
            )

        except json.JSONDecodeError as error:

            raise RuntimeError(
                "HALON evidence-selection planner "
                "did not return valid JSON.\n\n"
                "RAW PLANNER RESPONSE:\n"
                f"{text}\n\n"
                "JSON ERROR:\n"
                f"{error}"
            ) from error

        if not isinstance(
            selection_request,
            dict
        ):

            raise RuntimeError(
                "HALON evidence-selection request "
                "must be a JSON object."
            )

        requests = (
            selection_request.get(
                "requests"
            )
        )

        if not isinstance(
            requests,
            list
        ):

            raise RuntimeError(
                "HALON evidence-selection request "
                "must contain a requests list."
            )

        # ----------------------------------------------------
        # VALIDATE AGAINST THE EVIDENCE CATALOG
        # ----------------------------------------------------

        validated_requests = []

        for request in requests:

            if not isinstance(
                request,
                dict
            ):

                raise RuntimeError(
                    "HALON evidence-selection request "
                    "contains an invalid request entry."
                )

            source = (
                request.get(
                    "source"
                )
            )

            if source not in evidence_catalog:

                raise RuntimeError(
                    "HALON evidence-selection planner "
                    f"requested unsupported source: {source}"
                )

            filters = (
                request.get(
                    "filters",
                    {}
                )
            )

            if not isinstance(
                filters,
                dict
            ):

                raise RuntimeError(
                    "HALON evidence-selection filters "
                    "must be a JSON object."
                )

            supported_filters = set(
                evidence_catalog[
                    source
                ].get(
                    "filters",
                    []
                )
            )

            for filter_name in filters:

                if (
                    filter_name
                    not in supported_filters
                ):

                    raise RuntimeError(
                        "HALON evidence-selection planner "
                        "requested unsupported filter "
                        f"'{filter_name}' for source "
                        f"'{source}'."
                    )

            limit = request.get(
                "limit",
                50
            )

            try:

                limit = int(
                    limit
                )

            except (
                TypeError,
                ValueError,
            ) as error:

                raise RuntimeError(
                    "HALON evidence-selection request "
                    "contains an invalid result limit."
                ) from error

            limit = max(
                1,
                min(
                    limit,
                    200
                )
            )

            order = request.get(
                "order"
            )

            if order is not None:

                if not isinstance(
                    order,
                    dict
                ):

                    raise RuntimeError(
                        "HALON evidence-selection order "
                        "must be a JSON object."
                    )

                order_by = order.get(
                    "by"
                )

                direction = order.get(
                    "direction"
                )

                if order_by != "time":

                    raise RuntimeError(
                        "HALON currently supports only "
                        "time-based evidence ordering."
                    )

                if direction not in (
                    "ascending",
                    "descending",
                ):

                    raise RuntimeError(
                        "HALON evidence ordering direction "
                        "must be ascending or descending."
                    )

            validated_requests.append(
                {
                    "source":
                        source,

                    "filters":
                        filters,

                    "order":
                        order,

                    "limit":
                        limit,
                }
            )

        return {
            "requests":
                validated_requests
        }