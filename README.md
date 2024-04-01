# 食用方法
```
Usage: openai_token.py [OPTIONS]

Options:
  -p, --proxy TEXT     A http proxy str. (http://127.0.0.1:8080)
  -r, --refresh_token  Get refresh token.
  -a, --access_token   Get access token.
  -s, --sess_key       Get sess key.
  --help               Show this message and exit.
```

# 栗子：

```
<script/execute> -p http://127.0.0.1:1082 -rsa
```
会打印`refresh token` `sess key` `access token`