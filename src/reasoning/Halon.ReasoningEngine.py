from pathlib import Path
from typing import Any
import json

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
        thread_count: int = 8,
    ) -> None:

        if not model_path.exists():

            raise FileNotFoundError(
                f"HALON reasoning model not found: "
                f"{model_path}"
            )

        self.model_path = model_path

        self.model = Llama(
            model_path=str(model_path),
            n_ctx=context_size,
            n_threads=thread_count,
            verbose=False,
        )

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

17. Do not create speculative hypotheses merely to populate the
    HYPOTHESES section.

18. A hypothesis must propose an explanation for unresolved
    observed behavior and must have positive supporting evidence.

    Mere possibility is not sufficient.

19. Presence, compatibility, temporal association, or an already
    established HALON relationship is not sufficient support for
    a hypothesis.

20. Do not use HYPOTHESES to restate established evidence.

21. If the available evidence does not support a more specific
    explanation, state that explicitly.


OUTPUT DISCIPLINE

22. Interpretation boundaries are global evidentiary constraints.

    Do not repeat the same boundary beside every observation.

23. Prefer a concise answer.

    Tell the evidence story once and do not duplicate the same
    fact across sections.


OUTPUT FORMAT

Respond using exactly these four sections, in this order:


RECONSTRUCTED EVIDENCE

Answer the user's question using what HALON observed or
deterministically established.

Prefer chronological presentation when chronology materially
helps answer the question.

Include important evidence identifiers and deterministic
relationships when useful.

Do not interpret unresolved technical identifiers here.


HYPOTHESES

List only explanations positively supported by the supplied
evidence or authoritative knowledge.

Do not restate established evidence as a hypothesis.

If no evidence-supported explanatory hypothesis exists, write:

"The available evidence does not presently support a more
specific hypothesis."


KNOWLEDGE REQUIRED

Identify authoritative technical knowledge that would materially
improve the answer.

Prefer observations explicitly marked:

interpretationStatus = AuthoritativeReferenceRequired

Do not request knowledge merely to reinterpret deterministic
HALON relationships that are already established.

If no additional authoritative knowledge is required, state that
explicitly.


LIMITATIONS

State what the supplied evidence and knowledge cannot establish.

Include material uncertainty involving causation, intent,
responsibility, unavailable telemetry, reconstruction limits,
or unresolved technical interpretation.
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

Answer the user's question from the supplied HALON evidence.

Use explicit HALON relationships rather than deriving conflicting
relationships from lower-level fields.

Do not assume that every supplied piece of evidence is relevant.

Do not assign undocumented technical meaning to Windows values
unless authoritative knowledge supporting that interpretation
has been supplied.

If additional authoritative technical knowledge is materially
required, identify it under KNOWLEDGE REQUIRED.
""".strip()

    # ========================================================
    # REASONING
    # ========================================================

    def reason(
        self,
        question: str,
        evidence: dict[str, Any],
        knowledge: dict[str, Any] | None = None,
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

        response = (
            self.model.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content":
                            self.build_system_prompt(),
                    },
                    {
                        "role": "user",
                        "content":
                            self.build_user_prompt(
                                question=question,
                                evidence=evidence,
                                knowledge=knowledge,
                            ),
                    },
                ],
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

        return str(
            answer
        ).strip()