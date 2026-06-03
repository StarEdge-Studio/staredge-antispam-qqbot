from __future__ import annotations

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Violation(Base):
    __tablename__ = "violations"

    group_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    group_id: Mapped[int] = mapped_column(Integer, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    violated_at: Mapped[str] = mapped_column(String, nullable=False)
    violation_count: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_label: Mapped[str] = mapped_column(String, nullable=False)
    actions: Mapped[str] = mapped_column(String, nullable=False)
