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



### preauth_cookie如何生成？

1. 准备一台ios设备，想办法获取device token，详见[官方文档](https://developer.apple.com/documentation/devicecheck/dcdevice/generatetoken(completionhandler:))

2. 准备一个能访问openai的代理，发起以下请求即可得到preauth_cookie（device_id可自行修改）,就cookie而言是1小时后过期

   ```python
   rsp = requests.post(
       'https://ios.chat.openai.com/backend-api/preauth_devicecheck',
       json={
           "bundle_id": "com.openai.chat",
           "device_id": "12345678-042E-45C7-962F-AC725D0E7770",
           "device_token": "your device token",
           "request_flag": True
       },
       proxies={'all': 'http://127.0.0.1:8080'}
   )
   if rsp.status_code == 200:
       print(rsp.cookies['_preauth_devicecheck'])
   ```

3. 频繁使用其获取refresh token可能会封设备，原因可能是以下几个或之一：
   - 同一preauth_cookie多次用来获取refresh token
   - 同一device token生成的preauth_cookie用于大量用户账号登录
