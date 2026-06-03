from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime

from nonebot import logger
from nonebot.adapters.onebot.v11 import Bot, GroupMessageEvent, Message, MessageSegment
from nonebot.exception import ActionFailed

from .config import config
from .detection import RuleHit
from .utils import now_cn


RECENT_WINDOW_SECONDS = 600
recent_messages: defaultdict[tuple[int, int], deque[tuple[float, int]]] = defaultdict(deque)


def remember(event: GroupMessageEvent) -> None:
    key = (event.group_id, event.user_id)
    queue = recent_messages[key]
    now = datetime.now().timestamp()
    queue.append((now, event.message_id))
    # 只保留 10 分钟窗口内的消息，符合群消息可撤回时间窗口，也避免内存长期增长。
    while queue and now - queue[0][0] > RECENT_WINDOW_SECONDS:
        queue.popleft()


def actions_for_count(count: int) -> tuple[str, ...]:
    actions = list(config.single_actions)
    if config.escalation.enabled and count >= config.escalation.threshold:
        # 多次违规处置是在单次处置基础上追加，不覆盖单次处置。
        for action in config.escalation.actions:
            if action not in actions:
                actions.append(action)
    if "blacklist" in actions and "kick" not in actions:
        actions.insert(actions.index("blacklist"), "kick")
    return tuple(actions)


def actions_text(actions: tuple[str, ...]) -> str:
    names = {
        "recall": "撤回",
        "recall_related": "撤回相关所有消息",
        "warn": "警告",
        "kick": "移除",
        "blacklist": "拉黑",
    }
    return "、".join(names.get(action, action) for action in actions)


async def safe_delete(bot: Bot, message_id: int) -> None:
    try:
        await bot.delete_msg(message_id=message_id)
    except ActionFailed as exc:
        logger.warning(f"failed to recall message {message_id}: {exc}")


async def apply_actions(
    bot: Bot,
    event: GroupMessageEvent,
    actions: tuple[str, ...],
    warning_message: Message,
) -> None:
    if "recall" in actions:
        await safe_delete(bot, event.message_id)
    if "recall_related" in actions:
        key = (event.group_id, event.user_id)
        # 相关消息只撤回机器人运行期间记录到的同群同用户消息。
        for _, message_id in list(recent_messages[key]):
            await safe_delete(bot, message_id)
    if "warn" in actions:
        try:
            await bot.send_group_msg(group_id=event.group_id, message=warning_message)
        except ActionFailed as exc:
            logger.warning(f"failed to send warning for user {event.user_id}: {exc}")
    if "kick" in actions or "blacklist" in actions:
        reject = "blacklist" in actions
        try:
            # reject_add_request=true 表示踢出后拒绝再次加群，用作群内拉黑。
            await bot.set_group_kick(group_id=event.group_id, user_id=event.user_id, reject_add_request=reject)
        except ActionFailed as exc:
            logger.warning(f"failed to kick user {event.user_id}: {exc}")


def warning(event: GroupMessageEvent, hit: RuleHit, actions: tuple[str, ...], current_case_id: str) -> Message:
    admin = config.admins[0] if config.admins else 0
    message = Message()
    message += MessageSegment.at(event.user_id)
    message += MessageSegment.text(
        " 因违规被处置\n"
        f"处置规则：{hit.label}\n"
        f"处置措施：{actions_text(actions)}\n"
        f"处置编号：{current_case_id}\n"
        "处置负责人："
    )
    if admin:
        message += MessageSegment.at(admin)
    message += MessageSegment.text(
        "\n"
        f"申诉邮箱：{config.appeal_email}\n"
        f"处置时间：{now_cn().strftime('%Y-%m-%d %H:%M:%S CST')}\n"
        "【星缘工作室反黑产BOT】"
    )
    return message
