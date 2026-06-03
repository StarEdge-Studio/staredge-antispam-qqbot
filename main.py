import nonebot
from nonebot.adapters.onebot.v11 import Adapter as OneBotV11Adapter


nonebot.init(host="0.0.0.0", port=8080)
driver = nonebot.get_driver()
driver.register_adapter(OneBotV11Adapter)

nonebot.load_plugin("plugins.antispam")


def main() -> None:
    nonebot.run()


if __name__ == "__main__":
    main()
