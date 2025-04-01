import os
import yaml
from pathlib import Path
from dotenv import load_dotenv
from typing import Dict, Any

load_dotenv()


class Settings:
    # 基础配置
    REQUEST_TIMEOUT = 1
    MAX_CONCURRENT = 50
    USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0")

    # 项目根目录路径配置
    BASE_DIR = Path(__file__).parent
    # xray-core存放的文件夹
    XRAY_CORE_DIR = BASE_DIR / "xray-core"
    OUTPUT_DIR = BASE_DIR
    CONFIG_FILE = BASE_DIR / "config.yaml"

    # 协议配置
    SUPPORTED_PROTOCOLS = ["vmess", "vless"]

    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        """加载YAML配置文件"""
        if not cls.CONFIG_FILE.exists():
            raise FileNotFoundError(f"配置文件 {cls.CONFIG_FILE} 不存在")

        with open(cls.CONFIG_FILE) as f:
            return yaml.safe_load(f)

    @classmethod
    def setup(cls):
        """初始化目录结构"""
        cls.XRAY_CORE_DIR.mkdir(exist_ok=True)
        cls.OUTPUT_DIR.mkdir(exist_ok=True)
