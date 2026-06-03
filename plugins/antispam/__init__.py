from nonebot import get_driver, logger, on_message
from nonebot.adapters.onebot.v11 import Bot, GroupMessageEvent, MessageEvent
from nonebot.rule import Rule

from .actions import actions_for_count, apply_actions, remember, warning
from .config import config
from .database import bump_violation, init_database, write_audit
from .detection import detect
from .utils import case_id


matcher = on_message(Rule(lambda event: isinstance(event, GroupMessageEvent)), priority=1, block=False)


def _message_summary(event: GroupMessageEvent, limit: int = 200) -> str:
    content = str(event.message).replace("\n", "\\n")
    return content if len(content) <= limit else f"{content[:limit]}..."


def _is_exempt(event: GroupMessageEvent) -> bool:
    role = getattr(event.sender, "role", None)
    return role in {"owner", "admin"} or event.user_id in config.qq_whitelist


def _is_group_allowed(event: GroupMessageEvent) -> bool:
    return not config.group_whitelist or event.group_id in config.group_whitelist


@get_driver().on_startup
async def _startup() -> None:
    init_database()
    logger.info("antispam plugin loaded")


@matcher.handle()
async def _(bot: Bot, event: MessageEvent) -> None:
    if not isinstance(event, GroupMessageEvent):
        return
    if not _is_group_allowed(event):
        return
    if _is_exempt(event):
        return
    remember(event)
    hit, content = await detect(bot, event)
    if not hit:
        return

    # 命中后先持久化违规和审计，再执行处置，避免处置 API 失败导致审计缺失。
    count = bump_violation(event.group_id, event.user_id)
    actions = actions_for_count(count)
    current_case_id = case_id()
    write_audit(current_case_id, event.group_id, event.user_id, content, count, hit.label, actions)
    logger.warning(
        "antispam violation handled: "
        f"case_id={current_case_id} group={event.group_id} user={event.user_id} "
        f"message_id={event.message_id} count={count} rule={hit.label} "
        f"actions={','.join(actions)} content={_message_summary(event)}"
    )
    await apply_actions(bot, event, actions, warning(event, hit, actions, current_case_id))
