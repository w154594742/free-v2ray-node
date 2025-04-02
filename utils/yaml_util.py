import yaml
from pathlib import Path
from typing import Any, Union, Optional


class YamlHandler:
    """
    YAML 文件读写工具类
    功能：
    1. 读取YAML文件（支持安全加载）
    2. 写入YAML文件
    3. 自动处理文件路径
    4. 异常处理
    """

    @staticmethod
    def _read_yaml(file_path: Union[str, Path],
                   default: Optional[Any] = None,
                   encoding: str = 'utf-8') -> Any:
        """
        读取YAML文件内容
        :param file_path: 文件路径（字符串或Path对象）
        :param default: 当文件不存在时返回的默认值
        :param encoding: 文件编码
        :return: 解析后的Python对象
        """
        path = Path(file_path)
        try:
            with path.open('r', encoding=encoding) as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            if default is not None:
                return default
            raise
        except yaml.YAMLError as e:
            raise ValueError(f"YAML解析错误: {e}")(e)

    @staticmethod
    def write_yaml(data: Any,
                   file_path: Union[str, Path],
                   encoding: str = 'utf-8',
                   block_style: bool = True) -> None:
        """
        将数据写入YAML文件
        :param data: 要写入的Python对象
        :param file_path: 文件路径（字符串或Path对象）
        :param encoding: 文件编码
        :param block_style: 是否使用块样式格式化
        """
        path = Path(file_path)
        # 自动创建父目录
        path.parent.mkdir(parents=True, exist_ok=True)

        yaml_args = {
            'allow_unicode': True,
            'encoding': encoding,
            'sort_keys': False
        }

        if block_style:
            yaml_args['default_flow_style'] = False

        try:
            with path.open('w', encoding=encoding) as f:
                yaml.safe_dump(data, f, **yaml_args)
        except yaml.YAMLError as e:
            raise ValueError(f"YAML序列化错误: {e}") from e

    @staticmethod
    def safe_read_yaml(file_path: Union[str, Path],
                       encoding: str = 'utf-8') -> Any:
        """
        安全读取YAML文件（使用SafeLoader）
        :param file_path: 文件路径（字符串或Path对象）
        :param encoding: 文件编码
        :return: 解析后的Python对象
        """
        return YamlHandler._read_yaml(file_path, encoding=encoding)


# 使用示例
if __name__ == "__main__":
    # 写入示例
    sample_data = {
        'database': {
            'host': 'localhost',
            'port': 3306,
            'users': ['admin', 'user1', 'user2']
        },
        'debug': True
    }

    YamlHandler.write_yaml(sample_data, '../conf.yaml')

    # 安全读取示例
    safe_loaded = YamlHandler.safe_read_yaml('../config.yaml')
    print(safe_loaded)
