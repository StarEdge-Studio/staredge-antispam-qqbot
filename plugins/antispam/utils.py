from __future__ import annotations

import random
import string
from datetime import UTC, datetime, timedelta


def now_cn() -> datetime:
    return datetime.now(UTC) + timedelta(hours=8)


def case_id() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(8))
