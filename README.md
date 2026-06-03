星缘工作室 QQ 反黑产 BOT，基于 nonebot2 + OneBot v11。

## 功能

- TOML 配置：`antispam.toml`
- 域名黑/白名单二选一
- 二维码识别，并复用域名黑/白名单
- 关键词黑/白名单，支持列表或 txt 路径
- regex 黑/白名单，支持列表或 txt 路径
- 支持合并转发/嵌套消息中的文本、图片二维码检测
- 单次违规处置：撤回、撤回相关所有消息、警告、移除、拉黑
- 多次违规升级处置
- SQLite 存储违规次数和审计日志
- 群主、群管理员和 `qq_whitelist` 白名单用户跳过检测
- `group_whitelist` 为空时检测所有群，非空时只检测列表内群

## 部署方式一：直接部署完整机器人

适合没有现成 nonebot 项目，直接把本仓库作为 QQ 反黑产机器人运行。

### 1. 安装依赖

```bash
uv sync
```

### 2. 修改配置

编辑 `antispam.toml`：

- `admins`：处置负责人 QQ，可配置多个，警告内容默认使用第一个。
- `qq_whitelist`：跳过检测的 QQ 白名单。
- `group_whitelist`：群白名单，空列表检测所有群，非空时只检测列表中的群。
- `appeal_email`：申诉邮箱。
- `[domain]`：域名黑/白名单，`mode` 只能为 `blacklist` 或 `whitelist`。
- `[qr]`：是否启用二维码识别。
- `[keyword]`：关键词识别，可为 `blacklist`、`whitelist` 或 `off`。
- `[regex]`：正则识别，可为 `blacklist`、`whitelist` 或 `off`。
- `[punishment]`：单次违规处置措施。
- `[escalation]`：多次违规升级处置措施。

### 3. 启动机器人

```bash
uv run python main.py
```

也可以使用脚本入口：

```bash
uv run staredge-antispam-qqbot
```

修改 `antispam.toml` 后重启生效。

## 部署方式二：作为插件接入已有 nonebot 项目

适合你已经有一个 nonebot2 项目，只想添加反黑产功能。

### 1. 安装依赖

在已有 nonebot 项目中安装依赖：

```bash
uv add nonebot-adapter-onebot httpx opencv-contrib-python-headless numpy
```

如果项目没有安装 nonebot2，也需要安装：

```bash
uv add "nonebot2[fastapi]"
```

### 2. 复制插件目录

将本仓库的 `plugins/antispam` 复制到你现有项目的插件目录，例如：

```text
your-nonebot-project/
  bot.py 或 main.py
  plugins/
    antispam/
      __init__.py
```

### 3. 复制配置文件

将 `antispam.toml` 放到你启动 nonebot 时的工作目录。

通常就是执行 `python main.py` 或 `nb run` 所在的项目根目录：

```text
your-nonebot-project/
  antispam.toml
  plugins/
    antispam/
```

插件会从当前工作目录读取：

```text
antispam.toml
```

### 4. 加载插件

如果你的项目手动加载插件，在入口中加入：

```python
nonebot.load_plugin("plugins.antispam")
```

示例：

```python
import nonebot
from nonebot.adapters.onebot.v11 import Adapter as OneBotV11Adapter

nonebot.init()
driver = nonebot.get_driver()
driver.register_adapter(OneBotV11Adapter)

nonebot.load_plugin("plugins.antispam")

if __name__ == "__main__":
    nonebot.run()
```

如果你的项目使用 `pyproject.toml` 或 nonebot 配置自动加载插件，请将插件名加入对应配置。

### 5. 启动现有项目

按你原项目的方式启动即可，例如：

```bash
uv run python main.py
```

或：

```bash
uv run nb run
```

## OneBot 连接说明

本项目使用 `nonebot-adapter-onebot`，需要配合 OneBot v11 实现端，例如 Lagrange.OneBot、NapCat、go-cqhttp 等。

nonebot 负责运行机器人逻辑，OneBot 实现端负责连接 QQ。请确保 OneBot 实现端能连接到 nonebot，并且机器人具有以下群权限：

- 撤回消息
- 踢出群成员
- 拒绝再次加群，作为拉黑效果
- 发送群消息和 @ 成员

## txt 规则文件

配置项 `rules` 可写为列表：

```toml
rules = ["example.com", "bad.example"]
```

也可写为 txt 路径：

```toml
rules = "lists/domain_blacklist.txt"
```

txt 文件每行一条规则，空行和 `#` 开头的行会被忽略。

## 数据存储

SQLite 数据库路径由 `antispam.toml` 的 `[audit].database` 配置，默认：

```toml
[audit]
database = "data/antispam.sqlite3"
```

数据库会记录：

- 违规次数
- 审计日志
- 处置编号
- 违规人 QQ
- 违规消息内容
- 违规时间
- 处置规则
- 处置措施
