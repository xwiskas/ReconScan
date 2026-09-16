"""The shape every tool in the catalog has.

One tool module = one real CLI program. It declares:

  TOOL   - the beginner "tool card" plus the goals you can pick
  build  - goal + options -> a validated argv list (never a shell string)
  parse  - raw output -> structured findings

Because build() returns a list, the same list is used for BOTH the preview you
read and the process we execute. There is no second code path that could run
something different from what you were shown (PRD G2 / "one immutable ScanPlan").
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class Option:
    """One control in the scan builder form."""
    id: str
    label: str
    type: str                      # bool | select | text | number
    default: Any
    help: str                      # plain-English "what this does"
    choices: list[dict] = field(default_factory=list)  # [{value,label,help}]
    placeholder: str = ""
    advanced: bool = False
    min: int | None = None
    max: int | None = None

    def as_json(self) -> dict:
        return {
            "id": self.id, "label": self.label, "type": self.type,
            "default": self.default, "help": self.help, "choices": self.choices,
            "placeholder": self.placeholder, "advanced": self.advanced,
            "min": self.min, "max": self.max,
        }


@dataclass(frozen=True)
class Goal:
    """A plain-English thing you might want to find out about a target."""
    id: str
    label: str                     # "Find open ports"
    blurb: str                     # one sentence, no jargon
    detail: str                    # 2-4 sentences: what / why / when
    options: list[Option] = field(default_factory=list)
    target_types: tuple[str, ...] = ("ip", "cidr", "range", "host", "url")
    root_recommended: bool = False
    typical_duration: str = "under a minute"

    def as_json(self) -> dict:
        return {
            "id": self.id, "label": self.label, "blurb": self.blurb,
            "detail": self.detail, "options": [o.as_json() for o in self.options],
            "target_types": list(self.target_types),
            "root_recommended": self.root_recommended,
            "typical_duration": self.typical_duration,
        }


@dataclass(frozen=True)
class Card:
    """The beginner tool card (PRD F4)."""
    what: str
    why: str
    when: str
    noise: str                     # how loud/detectable this tool is
    safe_default: str
    docs: str = ""

    def as_json(self) -> dict:
        return {"what": self.what, "why": self.why, "when": self.when,
                "noise": self.noise, "safe_default": self.safe_default, "docs": self.docs}


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    binary: str
    category: str
    card: Card
    goals: list[Goal]
    flag_help: dict[str, str]      # "-sV" -> "Ask each open port what software..."
    needs_root: bool = False

    def goal(self, goal_id: str) -> Goal:
        for g in self.goals:
            if g.id == goal_id:
                return g
        raise KeyError(goal_id)

    def as_json(self) -> dict:
        return {
            "id": self.id, "name": self.name, "binary": self.binary,
            "category": self.category, "card": self.card.as_json(),
            "goals": [g.as_json() for g in self.goals],
            "flag_help": self.flag_help, "needs_root": self.needs_root,
        }


@dataclass(frozen=True)
class Warning_:
    """A guardrail message shown on the preflight screen (PRD A3)."""
    level: str                     # info | caution | danger
    title: str
    body: str

    def as_json(self) -> dict:
        return {"level": self.level, "title": self.title, "body": self.body}


@dataclass
class BuildResult:
    args: list[str]                       # argv AFTER the binary name
    warnings: list[Warning_] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    est_seconds: int = 30


@dataclass
class ScanPlan:
    """Immutable-by-convention plan: what you preview is what we execute."""
    tool_id: str
    tool_name: str
    binary: str
    goal_id: str
    goal_label: str
    target: str
    argv: list[str]                       # binary + args, ready for exec
    warnings: list[Warning_]
    notes: list[str]
    explained: list[dict]                 # [{token, help}] for the preview
    host_count: int
    est_seconds: int
    needs_root: bool

    @property
    def preview(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    def as_json(self) -> dict:
        return {
            "tool_id": self.tool_id, "tool_name": self.tool_name,
            "goal_id": self.goal_id, "goal_label": self.goal_label,
            "target": self.target, "argv": self.argv, "preview": self.preview,
            "warnings": [w.as_json() for w in self.warnings], "notes": self.notes,
            "explained": self.explained, "host_count": self.host_count,
            "est_seconds": self.est_seconds, "needs_root": self.needs_root,
        }


def finding(target: str, ftype: str, data: dict) -> dict:
    """A parsed result row, pre-interpretation."""
    return {"target": target, "type": ftype, "data": data}


# Shared option used by every tool's Advanced panel.
RAW_FLAGS = Option(
    id="raw_flags",
    label="Extra raw flags (advanced)",
    type="text",
    default="",
    help=("Anything you type here is appended to the command as separate arguments. "
          "This is the escape hatch: once you know the CLI, you are not limited by "
          "this UI. Shell characters like ; | & are refused - ReconScan never runs a "
          "shell, so they would not do what you expect anyway."),
    placeholder="--reason --open",
    advanced=True,
)

BuildFn = Callable[[str, str, dict], BuildResult]
