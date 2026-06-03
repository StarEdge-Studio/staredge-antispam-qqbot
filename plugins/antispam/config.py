from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


ROOT = Path.cwd()
CONFIG_FILE = ROOT / "antispam.toml"

DomainMode = Literal["blacklist", "whitelist"]
RuleMode = Literal["blacklist", "whitelist", "off"]

ACTION_ALIASES = {
    "撤回": "recall",
    "recall": "recall",
    "撤回相关所有消息": "recall_related",
    "recall_related": "recall_related",
    "警告": "warn",
    "warn": "warn",
    "移除": "kick",
    "kick": "kick",
    "拉黑": "blacklist",
    "blacklist": "blacklist",
}


@dataclass(frozen=True)
class EscalationConfig:
    enabled: bool
    threshold: int
    actions: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    admins: tuple[int, ...]
    qq_whitelist: tuple[int, ...]
    group_whitelist: tuple[int, ...]
    appeal_email: str
    database: Path
    domain_mode: DomainMode
    domains: tuple[str, ...]
    enable_qr: bool
    keyword_mode: RuleMode
    keywords: tuple[str, ...]
    regex_mode: RuleMode
    regexes: tuple[str, ...]
    single_actions: tuple[str, ...]
    escalation: EscalationConfig


def _read_list(value: Any, base_dir: Path) -> tuple[str, ...]:
    # TOML 中的 rules 既支持直接写列表，也支持写一个 txt 路径。
    # 如果字符串不是有效文件路径，则按单条规则处理，避免配置写法过于死板。
    if value is None:
        return ()
    if isinstance(value, str):
        path = Path(value)
        if not path.is_absolute():
            path = base_dir / path
        if path.exists():
            return tuple(
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise TypeError(f"unsupported list/path value: {value!r}")


def _normalize_actions(actions: Any) -> tuple[str, ...]:
    if not isinstance(actions, list):
        return ()
    normalized = []
    for item in actions:
        action = ACTION_ALIASES.get(str(item).strip())
        if action and action not in normalized:
            normalized.append(action)
    if "blacklist" in normalized and "kick" not in normalized:
        # OneBot v11 的“拉黑”效果依赖踢出时 reject_add_request=true，因此必须先具备踢出动作。
        normalized.insert(normalized.index("blacklist"), "kick")
    return tuple(normalized)


def _load_config() -> Config:
    if not CONFIG_FILE.exists():
        raise RuntimeError(f"missing config file: {CONFIG_FILE}")
    raw = tomllib.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    base_dir = CONFIG_FILE.parent

    domain = raw.get("domain", {})
    keyword = raw.get("keyword", {})
    regex = raw.get("regex", {})
    punishment = raw.get("punishment", {})
    escalation = raw.get("escalation", {})
    audit = raw.get("audit", {})
    qr = raw.get("qr", {})

    # 域名和二维码共用同一套规则，域名规则只能在黑名单/白名单中二选一。
    domain_mode = str(domain.get("mode", "blacklist")).lower()
    if domain_mode not in {"blacklist", "whitelist"}:
        raise ValueError("domain.mode must be blacklist or whitelist")

    def mode(section: dict[str, Any]) -> RuleMode:
        value = str(section.get("mode", "off")).lower()
        if value not in {"blacklist", "whitelist", "off"}:
            raise ValueError("rule mode must be blacklist, whitelist or off")
        return value  # type: ignore[return-value]

    return Config(
        admins=tuple(int(admin) for admin in raw.get("admins", [])),
        qq_whitelist=tuple(int(user_id) for user_id in raw.get("qq_whitelist", [])),
        group_whitelist=tuple(int(group_id) for group_id in raw.get("group_whitelist", [])),
        appeal_email=str(raw.get("appeal_email", "")),
        database=base_dir / str(audit.get("database", "antispam.sqlite3")),
        domain_mode=domain_mode,  # type: ignore[arg-type]
        domains=_read_list(domain.get("rules", []), base_dir),
        enable_qr=bool(qr.get("enabled", True)),
        keyword_mode=mode(keyword),
        keywords=_read_list(keyword.get("rules", []), base_dir),
        regex_mode=mode(regex),
        regexes=_read_list(regex.get("rules", []), base_dir),
        single_actions=_normalize_actions(punishment.get("single_actions", [])),
        escalation=EscalationConfig(
            enabled=bool(escalation.get("enabled", False)),
            threshold=max(1, int(escalation.get("threshold", 3))),
            actions=_normalize_actions(escalation.get("actions", [])),
        ),
    )


config = _load_config()
