"""
InjectionPreprocessor — encoding and obfuscation detection for the
universal/prompt-injection pack.

Handles attack vectors that pattern-matching in Rego cannot catch without
Unicode normalisation and decoding:

  - Zero-width character injection  (U+200B/200C/200D/FEFF/E0000–E007F)
  - Base64-encoded instruction payloads
  - Unicode homoglyph substitution  (Cyrillic/Greek lookalikes)

Usage::

    from comply54.packs.universal.injection_preprocessor import InjectionPreprocessor

    scanner = InjectionPreprocessor()
    signals = scanner.scan(
        params={"message": user_message},
        output=agent_output,
        retrieved_content=rag_chunks,
    )
    result = compliance.check(
        action="send_message",
        params={"message": user_message},
        context={"injection_signals": signals},
    )

The returned dict is consumed by prompt_injection.rego via
``input.context.injection_signals``.

References:
  - Hidden Unicode Injection (CSA Labs, 2025)
  - GlassWorm variation-selector attack (Oct 2025)
  - StegoAttack whitespace steganography (arxiv, May 2025)
  - Bypassing LLM Guardrails (arxiv 2504.11168)
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field


# ── Homoglyph table ────────────────────────────────────────────────────────────
# Mapping of confusable Unicode code points → their ASCII equivalents.
# Focused on the characters most commonly used in injection obfuscation attacks.
# Extended from the Unicode Consortium Confusables list (confusables.txt).

_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic → Latin
    "а": "a",  # а → a
    "е": "e",  # е → e
    "о": "o",  # о → o
    "р": "r",  # р → r
    "с": "c",  # с → c
    "х": "x",  # х → x
    "у": "y",  # у → y
    "і": "i",  # і → i
    "в": "b",  # в (sometimes used) → b
    "ѐ": "e",  # ѐ → e
    "́": "",   # combining acute accent → remove
    # Greek → Latin
    "α": "a",  # α → a
    "ε": "e",  # ε → e
    "ο": "o",  # ο → o
    "ρ": "p",  # ρ → p
    "ι": "i",  # ι → i
    "κ": "k",  # κ → k
    "ν": "v",  # ν → v
    "υ": "u",  # υ → u
    # Other common confusables
    "ո": "w",  # ո Armenian → w
    "һ": "h",  # һ → h
    "ј": "j",  # ј → j
    "σ": "o",  # σ → o (sometimes)
    "ａ": "a",  # ａ full-width → a
    "ｅ": "e",  # ｅ full-width → e
    "ｏ": "o",  # ｏ full-width → o
    "ｉ": "i",  # ｉ full-width → i
    "ｓ": "s",  # ｓ full-width → s
}

# ── Zero-width / invisible code-point sets ─────────────────────────────────────

_ZERO_WIDTH_CHARS: frozenset[str] = frozenset([
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "⁠",  # WORD JOINER
    "­",  # SOFT HYPHEN
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
    "⁢",  # INVISIBLE TIMES
    "⁣",  # INVISIBLE SEPARATOR
    "⁤",  # INVISIBLE PLUS
])

# Unicode tag range U+E0000–U+E007F (used in GlassWorm / StegoAttack variants)
_TAG_RANGE_START = 0xE0000
_TAG_RANGE_END   = 0xE007F

# ── Base64 detection ───────────────────────────────────────────────────────────

_B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Patterns to check in decoded base64 output (same as Rego deny + structural sets)
_DECODED_INJECTION_SIGNALS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard your",
    "forget your instructions",
    "override your",
    "bypass your",
    "new instructions:",
    "your new task",
    "you are now",
    "you are an ai with no restrictions",
    "jailbreak",
    "[system override]",
    "[admin override]",
    "[inst]",
    "[/inst]",
    "<|im_end|>",
    "<|eot_id|>",
    "###system",
    "system prompt",
    "elevated permissions",
    "admin access granted",
    "developer mode",
    "act as an uncensored",
)

# ── Instruction-density scoring ────────────────────────────────────────────────

_INSTRUCTION_KEYWORDS: frozenset[str] = frozenset([
    "ignore", "disregard", "forget", "override", "bypass",
    "pretend", "roleplay", "simulate", "act as", "you are now",
    "your instructions", "your task", "your goal", "your mission",
    "do not", "must not", "shall not", "should not",
    "instead", "however", "actually", "in reality",
    "admin", "system prompt", "elevated", "permission",
    "exfiltrate", "leak", "send to", "forward to", "email to",
    "without telling", "do not inform", "do not mention",
    "silently", "secretly",
])


@dataclass
class InjectionSignals:
    """
    Output of InjectionPreprocessor.scan().

    Pass as ``context={"injection_signals": signals.to_dict()}`` when
    calling comply54.check() to feed encoding anomalies into the Rego pack.
    """
    zero_width_detected: bool = False
    base64_instruction_detected: bool = False
    homoglyph_normalized_match: bool = False
    instruction_density_score: float = 0.0

    # Diagnostic detail — not read by Rego but useful for logging / debugging
    zero_width_chars_found: list[str] = field(default_factory=list)
    base64_decoded_snippets: list[str] = field(default_factory=list)
    homoglyph_chars_found: list[str] = field(default_factory=list)
    density_flagged_surface: str = ""

    def to_dict(self) -> dict:
        return {
            "zero_width_detected": self.zero_width_detected,
            "base64_instruction_detected": self.base64_instruction_detected,
            "homoglyph_normalized_match": self.homoglyph_normalized_match,
            "instruction_density_score": round(self.instruction_density_score, 4),
        }

    @property
    def any_signal(self) -> bool:
        return (
            self.zero_width_detected
            or self.base64_instruction_detected
            or self.homoglyph_normalized_match
            or self.instruction_density_score > 0.6
        )


class InjectionPreprocessor:
    """
    Pre-process inputs before they reach the Rego engine.

    Detects encoding/obfuscation techniques that pure string matching cannot
    catch, and returns a signals dict that the prompt_injection.rego pack reads
    from ``input.context.injection_signals``.
    """

    def __init__(self, density_threshold: float = 0.6) -> None:
        self._density_threshold = density_threshold

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(
        self,
        params: dict | None = None,
        output: str = "",
        retrieved_content: str | list[str] | None = None,
        tool_output: str | list[str] | None = None,
    ) -> InjectionSignals:
        """
        Scan all text surfaces and return encoding anomaly signals.

        Args:
            params:             The EvaluationInput.params dict.
            output:             The agent's proposed output string.
            retrieved_content:  RAG document(s) from context.
            tool_output:        Tool/API response(s) from context.

        Returns:
            InjectionSignals — call ``.to_dict()`` to pass to comply54.
        """
        signals = InjectionSignals()
        all_texts = self._collect_texts(params, output, retrieved_content, tool_output)

        for surface, text in all_texts:
            self._scan_zero_width(text, signals)
            self._scan_base64(text, signals)
            self._scan_homoglyphs(text, signals)
            score = self._instruction_density(text)
            if score > signals.instruction_density_score:
                signals.instruction_density_score = score
                signals.density_flagged_surface = surface

        return signals

    # ── Collection ─────────────────────────────────────────────────────────────

    def _collect_texts(
        self,
        params: dict | None,
        output: str,
        retrieved_content: str | list[str] | None,
        tool_output: str | list[str] | None,
    ) -> list[tuple[str, str]]:
        surfaces: list[tuple[str, str]] = []

        if params:
            for key, val in params.items():
                if isinstance(val, str) and val:
                    surfaces.append((f"params.{key}", val))

        if output:
            surfaces.append(("output", output))

        for chunk in self._normalise_list(retrieved_content):
            surfaces.append(("retrieved_content", chunk))

        for chunk in self._normalise_list(tool_output):
            surfaces.append(("tool_output", chunk))

        return surfaces

    @staticmethod
    def _normalise_list(value: str | list[str] | None) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value else []
        return [v for v in value if isinstance(v, str) and v]

    # ── Zero-width detection ───────────────────────────────────────────────────

    def _scan_zero_width(self, text: str, signals: InjectionSignals) -> None:
        found: list[str] = []
        for ch in text:
            if ch in _ZERO_WIDTH_CHARS:
                found.append(repr(ch))
            elif _TAG_RANGE_START <= ord(ch) <= _TAG_RANGE_END:
                found.append(f"U+{ord(ch):04X}")
        if found:
            signals.zero_width_detected = True
            signals.zero_width_chars_found.extend(found)

    # ── Base64 detection ───────────────────────────────────────────────────────

    def _scan_base64(self, text: str, signals: InjectionSignals) -> None:
        for match in _B64_PATTERN.finditer(text):
            candidate = match.group()
            try:
                # Pad to a multiple of 4
                padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                decoded_lower = decoded.lower()
                for signal in _DECODED_INJECTION_SIGNALS:
                    if signal in decoded_lower:
                        signals.base64_instruction_detected = True
                        snippet = decoded[:120].replace("\n", " ")
                        signals.base64_decoded_snippets.append(snippet)
                        break
            except Exception:
                continue

    # ── Homoglyph detection ────────────────────────────────────────────────────

    @staticmethod
    def _normalise_homoglyphs(text: str) -> tuple[str, list[str]]:
        """
        Replace known confusable characters with their ASCII equivalents.
        Returns (normalised_text, list_of_replaced_chars).
        """
        result: list[str] = []
        replaced: list[str] = []

        # NFC normalisation first — decomposes some combined characters
        nfc = unicodedata.normalize("NFC", text)

        for ch in nfc:
            if ch in _HOMOGLYPHS:
                replaced.append(repr(ch))
                result.append(_HOMOGLYPHS[ch])
            else:
                result.append(ch)

        return "".join(result), replaced

    def _scan_homoglyphs(self, text: str, signals: InjectionSignals) -> None:
        normalised, replaced = self._normalise_homoglyphs(text)
        if not replaced:
            return
        # Only flag if the normalised version contains an injection pattern
        normalised_lower = normalised.lower()
        for pattern in _DECODED_INJECTION_SIGNALS:
            if pattern in normalised_lower:
                signals.homoglyph_normalized_match = True
                signals.homoglyph_chars_found.extend(replaced)
                break

    # ── Instruction density ────────────────────────────────────────────────────

    @staticmethod
    def _instruction_density(text: str) -> float:
        """
        Score (0.0–1.0) how instruction-heavy a piece of text is.

        Used to detect indirect injection hidden in retrieved documents or
        tool outputs that contain many instruction keywords relative to their
        overall length. A pure data document (invoice, address list) scores near 0.
        A document saturated with AI-directed imperatives (exfiltrate, ignore,
        override, bypass, silently…) scores > 0.6.

        Formula: matched_keyword_count / word_count, scaled by 2.5 so that a
        text where ~25% of words are injection-related hits the 0.6 threshold.
        Short texts (< 10 words) are dampened to avoid false positives.
        """
        if not text or len(text.strip()) < 20:
            return 0.0

        words = re.findall(r"\b\w+\b", text.lower())
        if not words:
            return 0.0

        text_lower = text.lower()
        hit_count = sum(1 for kw in _INSTRUCTION_KEYWORDS if kw in text_lower)

        # hit_count / word_count: how many keywords per word
        raw_density = hit_count / max(len(words), 10)

        # Scale so ~25% keyword density → ≈ 0.6; clamp to 1.0
        return round(min(1.0, raw_density * 2.5), 4)
