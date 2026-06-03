from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import cv2
import httpx
import numpy as np
from nonebot import logger
from nonebot.adapters.onebot.v11 import Bot, GroupMessageEvent, Message, MessageSegment

from .config import RuleMode, config


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
        if self.mode == "whitelist" and self.rule == "<not in whitelist>":
            return f"{self.kind}{mode_name}外"
        return f"{self.kind}{mode_name}-第{self.index}条"


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
    # OneBot 图片段通常只提供 URL，这里下载后使用 OpenCV contrib 的微信二维码检测器。
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
    data = np.frombuffer(response.content, dtype=np.uint8)
    image = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if image is None:
        return []
    if not hasattr(cv2, "wechat_qrcode_WeChatQRCode"):
        logger.warning("OpenCV WeChatQRCode is unavailable; install opencv-contrib-python-headless")
        return []
    detector = cv2.wechat_qrcode_WeChatQRCode()
    decoded, _ = detector.detectAndDecode(image)
    return [item for item in decoded if item]


def _to_message(content: Any) -> Message:
    if isinstance(content, Message):
        return content
    if isinstance(content, str):
        return Message(content)
    if isinstance(content, dict) and "type" in content:
        return Message(MessageSegment(str(content["type"]), dict(content.get("data") or {})))
    if isinstance(content, list):
        message = Message()
        for item in content:
            if isinstance(item, MessageSegment):
                message.append(item)
            elif isinstance(item, dict) and "type" in item:
                # get_forward_msg 返回的是 OneBot 原始消息段字典列表，需要先转为 MessageSegment。
                message.append(MessageSegment(str(item["type"]), dict(item.get("data") or {})))
            elif isinstance(item, str):
                message.extend(Message(item))
            else:
                logger.warning(f"ignored unsupported forward message segment: {item!r}")
        return message
    logger.warning(f"ignored unsupported forward message content: {content!r}")
    return Message()


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
            nested = _to_message(data["content"])
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
        nested = _to_message(content)
        nested_texts, nested_images = await _extract_message(bot, nested)
        texts.extend(nested_texts)
        images.extend(nested_images)
    return texts, images


async def detect(bot: Bot, event: GroupMessageEvent) -> tuple[RuleHit | None, str]:
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
