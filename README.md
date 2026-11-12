雷池WAF行为验证绕过是一个用 Python 编写的单文件脚本，用于完成雷池 WAF 的行为验证流程。脚本从响应中提取客户端 ID，请求验证数据，计算结果并提交校验，最后携带返回的 Cookie 重新访问目标地址。

先安装依赖，再传入目标地址：

```bash
pip install requests urllib3
python challenge.py http://target.example/
```

脚本只接受一个目标地址参数。虽然实际请求使用该地址的协议和主机部分，但传入时仍应填写完整的 HTTP 或 HTTPS 地址。

计算函数会结合输入长度、字节总和、乘法、异或和三次方运算生成整数，再将其编码为一组 6 比特值，即 0 到 63 的数值。

完整的 HTTP 请求流程都保留在一个文件中，便于查看。脚本先从响应中提取 `SafeLineChallenge` 的客户端 ID，再请求 `/.safeline/challenge/v2/api/issue` 获取验证数据，并使用 `calc` 函数计算结果。随后请求 `/.safeline/challenge/v2/api/verify` 提交结果，将返回的 JWT 写入 `sl-challenge-jwt` Cookie 后重新请求目标地址，最后根据最终响应的状态码和页面内容判断是否通过验证。

仅供安全研究和已授权测试使用。
