from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import config
from .models import AuditLog, Base, Violation
from .utils import now_cn


engine = create_engine(f"sqlite:///{config.database.as_posix()}", future=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def init_database() -> None:
    config.database.parent.mkdir(parents=True, exist_ok=True)
    # ORM 负责建表，避免业务代码里散落手写 SQL。
    Base.metadata.create_all(engine)


def bump_violation(group_id: int, user_id: int) -> int:
    now = now_cn().isoformat(timespec="seconds")
    with SessionLocal() as session:
        violation = session.get(Violation, {"group_id": group_id, "user_id": user_id})
        if violation is None:
            violation = Violation(group_id=group_id, user_id=user_id, count=0, updated_at=now)
            session.add(violation)
        violation.count += 1
        violation.updated_at = now
        # 违规次数以“群 + 用户”为维度累计，避免不同群的违规记录互相影响。
        session.commit()
        return violation.count


def write_audit(
    current_case_id: str,
    group_id: int,
    user_id: int,
    content: str,
    count: int,
    rule_label: str,
    actions: tuple[str, ...],
) -> None:
    with SessionLocal() as session:
        session.add(
            AuditLog(
                id=current_case_id,
                group_id=group_id,
                user_id=user_id,
                content=content,
                violated_at=now_cn().isoformat(timespec="seconds"),
                violation_count=count,
                rule_label=rule_label,
                actions=",".join(actions),
            )
        )
        session.commit()
