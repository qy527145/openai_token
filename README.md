# 本地使用

首先克隆本项目
```bash
git clone https://github.com/qy527145/openai_token.git
```

然后进入文件夹
```bash
cd openai_token
```

然后使用pip下载所需Python包
```python
pip install -r requirements.txt
```

# 食用方法

```
Usage: openai_token.py [OPTIONS]

Options:
  -p, --proxy TEXT     A http proxy str. (http://127.0.0.1:8080)
  -r, --refresh_token  Get refresh token.
  -a, --access_token   Get access token.
  -s, --sess_key       Get sess key.
  -f, --share-token    Get share key.
  --help               Show this message and exit.
```

# 栗子：

```
<script/execute> -p http://127.0.0.1:1082 -rsaf
```
会打印`refresh token` `sess key` `access token` `share_token`


### preauth_cookie如何生成？

1. 准备一台ios设备，想办法获取device token，device token是什么详见[官方文档](https://developer.apple.com/documentation/devicecheck/dcdevice/generatetoken(completionhandler:))，具体的获取方法看[这里](https://linux.do/t/topic/57756)

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

   脚本中已添加相关逻辑，只需提前设置device_token即可

3. 频繁使用其获取refresh token可能会封设备，原因可能是以下几个或之一：

   - 同一preauth_cookie多次用来获取refresh token
   - 同一device token生成的preauth_cookie用于大量用户账号登录
# 许可证

本项目使用[Apache License Version 2.0](LICENSE)许可证
