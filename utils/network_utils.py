import requests


class HttpRequestTool:
    """
    一个简单的HTTP请求工具类，用于发送和处理HTTP请求。
    """

    def __init__(self, headers=None, timeout=10):
        """
        初始化工具类。
        :param headers: 默认请求头，可选
        :param timeout: 默认超时时间，单位秒
        """
        self.base_url = ""  # 初始为空，需通过 set_base_url 方法设置
        self.headers = headers if headers else {}
        self.timeout = timeout

    def set_base_url(self, base_url):
        """
        设置基础URL。
        :param base_url: 基础URL
        """
        self.base_url = base_url.rstrip("/") if base_url else ""
        return self  # 支持链式调用

    def set_browser_headers(self, custom_headers=None):
        """
        设置通用的浏览器请求头，并支持自定义头部信息。
        :param custom_headers: 用户自定义的头部信息，字典格式
        """
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        # 合并默认头部和自定义头部
        if custom_headers:
            default_headers.update(custom_headers)
        self.headers.update(default_headers)
        return self  # 支持链式调用

    def _send_request(self, method, endpoint="", params=None, data=None, json=None, headers=None, timeout=None):
        """
        发送HTTP请求。
        :param method: 请求方法 (GET, POST, PUT, DELETE等)
        :param endpoint: 请求的路径或完整URL，默认为空字符串
        :param params: 查询参数 (用于GET请求)
        :param data: 表单数据 (用于POST请求)
        :param json: JSON数据 (用于POST请求)
        :param headers: 请求头
        :param timeout: 超时时间，默认使用初始化时的超时时间
        :return: 响应对象
        """
        # 如果 endpoint 为空，则直接使用 base_url
        url = f"{self.base_url}{'' if not endpoint else '/' + endpoint.lstrip('/')}"
        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)

        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json,
                headers=request_headers,
                timeout=timeout or self.timeout
            )
            resp.raise_for_status()  # 如果响应状态码不是200-299，抛出HTTPError
            return resp
        except requests.exceptions.RequestException as e:
            print(f"请求失败: {e} (URL: {url})")
            return None

    def get(self, endpoint, **kwargs):
        """
        发送GET请求。
        """
        return self._send_request("GET", endpoint, **kwargs)

    def post(self, endpoint, **kwargs):
        """
        发送POST请求。
        """
        return self._send_request("POST", endpoint, **kwargs)

    def put(self, endpoint, **kwargs):
        """
        发送PUT请求。
        """
        return self._send_request("PUT", endpoint, **kwargs)

    def delete(self, endpoint, **kwargs):
        """
        发送DELETE请求。
        """
        return self._send_request("DELETE", endpoint, **kwargs)


# 示例用法
if __name__ == "__main__":
    # 链式调用示例，设置基础URL并添加自定义头部
    response = HttpRequestTool() \
        .set_base_url("https://raw.githubusercontent.com/cmliu/cmliu/main/SubsCheck-URLs") \
        .get("")
    
    if response:
        print("GET请求结果:", response.text)
