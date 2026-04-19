# openai_token

本地管理 OpenAI 账号的 `refresh_token`、`access_token`、`sess_key`，并支持多账号存储。

## 安装

```bash
pip install -r requirements.txt
```

## 存储格式

默认会写入 `./tokens.json`，格式如下：

```json
{
  "version": 2,
  "default_account": "main",
  "accounts": {
    "main": {
      "device_token": null,
      "refresh_token": "rt_xxx",
      "access_token": "eyJxxx",
      "sess_key": {
        "sess_key": "sess-xxxxxx",
        "created": "2026-04-19 10:30:01",
        "last_use": "2026-04-19 10:30:01"
      },
      "updated_at": "2026-04-19 10:30:01"
    }
  }
}
```

旧的单账号文件会在下次读写时自动兼容成多账号结构。

## 常用命令

查看帮助：

```bash
python openai_token.py --help
```

登录并保存一个账号：

```bash
python openai_token.py --account main --login
```

登录并指定 `device_token`：

```bash
python openai_token.py --account main --device-token your_device_token --login
```

列出全部账号：

```bash
python openai_token.py --list-accounts
```

获取指定账号的 token：

```bash
python openai_token.py --account main -r
python openai_token.py --account main -a
python openai_token.py --account main -s
python openai_token.py --account main -f
```

设置默认账号：

```bash
python openai_token.py --account main --set-default
```

删除账号：

```bash
python openai_token.py --account main --remove-account
```

指定自定义证书：

```bash
python openai_token.py --ca-bundle C:\\path\\to\\corp-ca.pem --account main -a
```

## 说明

- 网络层已从 `requests` 切换到 `httpx`。
- HTTPS 校验默认使用系统信任链，不再全局 `verify=False`。
- 如果代理是自签名证书，使用 `--ca-bundle` 传入 CA 文件。
- `-s/--sess-key` 获取到的 `sess_key` 会自动持久化到账号存储中。
