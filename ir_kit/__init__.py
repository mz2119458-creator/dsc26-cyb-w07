from dataclasses import dataclass
from datetime import datetime

GOVERNORATES: set[str] = {
    "01", "02", "03", "04",
    "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "21", "22", "23", "24", "25", "26", "27", "28", "29",
    "31", "32", "33", "34", "35",
    "88",
}


@dataclass(frozen=True)
class SecretFinding:
    path: str
    line: int
    column: int
    rule_id: str
    masked: str


@dataclass(frozen=True)
class Event:
    time: datetime
    source: str
    line: int
    message: str
