from __future__ import annotations

import asyncio
import random
import re
import sqlite3
import string
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import cv2
import httpx
import numpy as np
from nonebot import get_driver, logger, on_message
from nonebot.adapters.onebot.v11 import Bot, GroupMessageEvent, Message, MessageEvent
from nonebot.exception import ActionFailed
from nonebot.rule import Rule


ROOT = Path.cwd()
CONFIG_FILE = ROOT / "antispam.toml"
RECENT_WINDOW_SECONDS = 600

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
class RuleHit:
    kind: str
    mode: str
    index: int
    rule: str
    source: str

    @property
    def label(self) -> str:
        mode_name = "黑名单" if self.mode == "blacklist" else "白名单"
        return f"{self.kind}{mode_name}-第{self.index}条"


@dataclass(frozen=True)
class EscalationConfig:
    enabled: bool
    threshold: int
    actions: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    admins: tuple[int, ...]
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
# 用内存保存最近消息 ID，供“撤回相关所有消息”使用；重启后自然清空。
recent_messages: defaultdict[tuple[int, int], deque[tuple[float, int]]] = defaultdict(deque)
matcher = on_message(Rule(lambda event: isinstance(event, GroupMessageEvent)), priority=1, block=False)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.database)
    # WAL 降低读写互相阻塞的概率，适合机器人持续写入审计日志的场景。
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS violations (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            count INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            violated_at TEXT NOT NULL,
            violation_count INTEGER NOT NULL,
            rule_label TEXT NOT NULL,
            actions TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _now_cn() -> datetime:
    return datetime.now(UTC) + timedelta(hours=8)


def _case_id() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(8))


def _bump_violation(group_id: int, user_id: int) -> int:
    now = _now_cn().isoformat(timespec="seconds")
    with _connect() as conn:
        row = conn.execute(
            "SELECT count FROM violations WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        ).fetchone()
        count = int(row[0]) + 1 if row else 1
        # 违规次数以“群 + 用户”为维度累计，避免不同群的违规记录互相影响。
        conn.execute(
            """
            INSERT INTO violations(group_id, user_id, count, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(group_id, user_id)
            DO UPDATE SET count = excluded.count, updated_at = excluded.updated_at
            """,
            (group_id, user_id, count, now),
        )
        conn.commit()
    return count


def _write_audit(
    case_id: str,
    group_id: int,
    user_id: int,
    content: str,
    count: int,
    rule_label: str,
    actions: tuple[str, ...],
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs(id, group_id, user_id, content, violated_at, violation_count, rule_label, actions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                group_id,
                user_id,
                content,
                _now_cn().isoformat(timespec="seconds"),
                count,
                rule_label,
                ",".join(actions),
            ),
        )
        conn.commit()


def _remember(event: GroupMessageEvent) -> None:
    key = (event.group_id, event.user_id)
    queue = recent_messages[key]
    now = datetime.now().timestamp()
    queue.append((now, event.message_id))
    # 只保留 10 分钟窗口内的消息，符合群消息可撤回时间窗口，也避免内存长期增长。
    while queue and now - queue[0][0] > RECENT_WINDOW_SECONDS:
        queue.popleft()


def _extract_domains(text: str) -> list[str]:
    domains = []
    url_pattern = re.compile(r"(?i)\b(?:https?://)?([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+)\b")
    for match in url_pattern.finditer(text):
        host = match.group(1).lower().rstrip(".")
        parsed = urlparse(host if "://" in host else f"//{host}")
        domains.append((parsed.hostname or host).lower())
    return domains


def _domain_matches(domain: str, rule: str) -> bool:
    normalized = rule.lower().strip().lstrip(".")
    # 域名规则按主域匹配，配置 example.com 可覆盖 a.example.com 等子域。
    return domain == normalized or domain.endswith(f".{normalized}")


def _match_list(text: str, items: tuple[str, ...], mode: RuleMode, kind: str) -> RuleHit | None:
    if mode == "off" or not items or not text.strip():
        return None
    for index, item in enumerate(items, start=1):
        if item in text:
            # 黑名单命中即违规；白名单命中表示放行，所以不返回 RuleHit。
            return RuleHit(kind, mode, index, item, text) if mode == "blacklist" else None
    if mode == "whitelist":
        return RuleHit(kind, mode, 1, "<not in whitelist>", text)
    return None


def _match_regex(text: str) -> RuleHit | None:
    if config.regex_mode == "off" or not config.regexes or not text.strip():
        return None
    for index, pattern in enumerate(config.regexes, start=1):
        try:
            matched = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            # 单条非法正则不应拖垮整个机器人，记录告警后跳过该规则。
            logger.warning(f"invalid antispam regex #{index}: {pattern!r}: {exc}")
            continue
        if matched:
            return RuleHit("regex", config.regex_mode, index, pattern, text) if config.regex_mode == "blacklist" else None
    if config.regex_mode == "whitelist":
        return RuleHit("regex", config.regex_mode, 1, "<not in whitelist>", text)
    return None


def _match_domains(text: str, kind: str = "域名") -> RuleHit | None:
    domains = _extract_domains(text)
    if not config.domains or not domains:
        return None
    for domain in domains:
        for index, rule in enumerate(config.domains, start=1):
            if _domain_matches(domain, rule):
                if config.domain_mode == "blacklist":
                    return RuleHit(kind, config.domain_mode, index, rule, text)
                return None
    if config.domain_mode == "whitelist":
        return RuleHit(kind, config.domain_mode, 1, "<not in whitelist>", text)
    return None


def _detect_text(texts: list[str]) -> RuleHit | None:
    joined = "\n".join(text for text in texts if text)
    # 检测顺序决定审计中记录的首个命中规则：域名优先，其次关键词和正则。
    return (
        _match_domains(joined)
        or _match_list(joined, config.keywords, config.keyword_mode, "关键词")
        or _match_regex(joined)
    )


async def _decode_qr_from_url(url: str) -> list[str]:
    # OneBot 图片段通常只提供 URL，这里下载后用 OpenCV 同时尝试多码和单码识别。
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
    data = np.frombuffer(response.content, dtype=np.uint8)
    image = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if image is None:
        return []
    detector = cv2.QRCodeDetector()
    ok, decoded, _, _ = detector.detectAndDecodeMulti(image)
    if ok:
        return [item for item in decoded if item]
    single, _, _ = detector.detectAndDecode(image)
    return [single] if single else []


async def _extract_message(bot: Bot, message: Message) -> tuple[list[str], list[str]]:
    texts: list[str] = []
    image_urls: list[str] = []
    for segment in message:
        data = segment.data
        if segment.type == "text":
            texts.append(str(data.get("text", "")))
        elif segment.type == "image":
            url = data.get("url") or data.get("file")
            if url and str(url).startswith(("http://", "https://")):
                image_urls.append(str(url))
        elif segment.type == "forward" and data.get("id"):
            # 合并转发需要通过 get_forward_msg 拉取真实内容，再继续递归解析。
            nested_texts, nested_images = await _extract_forward(bot, str(data["id"]))
            texts.extend(nested_texts)
            image_urls.extend(nested_images)
        elif segment.type == "node" and data.get("content"):
            # node 里可能继续包含 MessageSegment，因此不能只按普通文本处理。
            content = data["content"]
            nested = content if isinstance(content, Message) else Message(content)
            nested_texts, nested_images = await _extract_message(bot, nested)
            texts.extend(nested_texts)
            image_urls.extend(nested_images)
    return texts, image_urls


async def _extract_forward(bot: Bot, forward_id: str) -> tuple[list[str], list[str]]:
    try:
        result = await bot.call_api("get_forward_msg", id=forward_id)
    except Exception as exc:
        logger.warning(f"failed to fetch forward message {forward_id}: {exc}")
        return [], []

    texts: list[str] = []
    images: list[str] = []
    messages = result.get("messages", []) if isinstance(result, dict) else []
    for item in messages:
        content = item.get("content") if isinstance(item, dict) else None
        if content is None:
            continue
        nested = content if isinstance(content, Message) else Message(content)
        nested_texts, nested_images = await _extract_message(bot, nested)
        texts.extend(nested_texts)
        images.extend(nested_images)
    return texts, images


async def _detect(bot: Bot, event: GroupMessageEvent) -> tuple[RuleHit | None, str]:
    texts, image_urls = await _extract_message(bot, event.message)
    visible_content = "\n".join(texts) or str(event.message)
    hit = _detect_text(texts)
    if hit or not config.enable_qr or not image_urls:
        return hit, visible_content

    qr_texts: list[str] = []
    # 文本规则未命中时才下载图片识别二维码，减少正常消息的网络和 CPU 开销。
    results = await asyncio.gather(*(_decode_qr_from_url(url) for url in image_urls), return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            logger.warning(f"failed to decode qr image: {result}")
            continue
        qr_texts.extend(result)
    qr_hit = _match_domains("\n".join(qr_texts), "域名")
    if qr_hit:
        visible_content = f"{visible_content}\n[二维码]\n" + "\n".join(qr_texts)
    return qr_hit, visible_content


def _actions_for_count(count: int) -> tuple[str, ...]:
    actions = list(config.single_actions)
    if config.escalation.enabled and count >= config.escalation.threshold:
        # 多次违规处置是在单次处置基础上追加，不覆盖单次处置。
        for action in config.escalation.actions:
            if action not in actions:
                actions.append(action)
    if "blacklist" in actions and "kick" not in actions:
        actions.insert(actions.index("blacklist"), "kick")
    return tuple(actions)


def _actions_text(actions: tuple[str, ...]) -> str:
    names = {
        "recall": "撤回",
        "recall_related": "撤回相关所有消息",
        "warn": "警告",
        "kick": "移除",
        "blacklist": "拉黑",
    }
    return "、".join(names.get(action, action) for action in actions)


async def _safe_delete(bot: Bot, message_id: int) -> None:
    try:
        await bot.delete_msg(message_id=message_id)
    except ActionFailed as exc:
        logger.warning(f"failed to recall message {message_id}: {exc}")


async def _apply_actions(
    bot: Bot,
    event: GroupMessageEvent,
    actions: tuple[str, ...],
    warning: str,
) -> None:
    if "recall" in actions:
        await _safe_delete(bot, event.message_id)
    if "recall_related" in actions:
        key = (event.group_id, event.user_id)
        # 相关消息只撤回机器人运行期间记录到的同群同用户消息。
        for _, message_id in list(recent_messages[key]):
            await _safe_delete(bot, message_id)
    if "warn" in actions:
        await bot.send_group_msg(group_id=event.group_id, message=Message(warning))
    if "kick" in actions or "blacklist" in actions:
        reject = "blacklist" in actions
        try:
            # reject_add_request=true 表示踢出后拒绝再次加群，用作群内拉黑。
            await bot.set_group_kick(group_id=event.group_id, user_id=event.user_id, reject_add_request=reject)
        except ActionFailed as exc:
            logger.warning(f"failed to kick user {event.user_id}: {exc}")


def _warning(event: GroupMessageEvent, hit: RuleHit, actions: tuple[str, ...], case_id: str) -> str:
    admin = config.admins[0] if config.admins else 0
    return (
        f"[CQ:at,qq={event.user_id}] 因违规被处置\n"
        f"处置规则：<{hit.label}>\n"
        f"处置措施：{_actions_text(actions)}\n"
        f"处置编号：<{case_id}>\n"
        f"处置负责人：[CQ:at,qq={admin}]\n"
        f"申诉邮箱：<{config.appeal_email}>\n"
        f"处置时间：<{_now_cn().strftime('%Y-%m-%d %H:%M:%S UTC+8')}>\n"
        "【星缘工作室反黑产BOT】"
    )


@get_driver().on_startup
async def _startup() -> None:
    config.database.parent.mkdir(parents=True, exist_ok=True)
    _connect().close()
    logger.info("antispam plugin loaded")


@matcher.handle()
async def _(bot: Bot, event: MessageEvent) -> None:
    if not isinstance(event, GroupMessageEvent):
        return
    _remember(event)
    hit, content = await _detect(bot, event)
    if not hit:
        return

    # 命中后先持久化违规和审计，再执行处置，避免处置 API 失败导致审计缺失。
    count = _bump_violation(event.group_id, event.user_id)
    actions = _actions_for_count(count)
    case_id = _case_id()
    _write_audit(case_id, event.group_id, event.user_id, content, count, hit.label, actions)
    await _apply_actions(bot, event, actions, _warning(event, hit, actions, case_id))
