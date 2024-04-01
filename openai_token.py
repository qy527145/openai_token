import base64
import hashlib
import json
import os
import time

import click
import requests
from DrissionPage import WebPage, ChromiumOptions


def to_time(t: int = None):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))


def to_timestamp(t: str = None):
    return time.strptime(t, '%Y-%m-%d %H:%M:%S') if t else time.time()


class TokenManager:
    def __init__(
            self,
            refresh_token=None,
            refresh_interval=60,
            storage_path='./token.json',
            proxy='http://127.0.0.1:1082',
    ):
        self.refresh_token = refresh_token
        self.refresh_interval = refresh_interval
        self.access_token = None
        self.storage_path = storage_path
        self.co = ChromiumOptions()
        if proxy:
            self.co.set_proxy(proxy)
            self.proxy = {'all': proxy}
        else:
            self.proxy = None
        self.load_token()

    def get_refresh_token(self):
        self.ensure_refresh_token()
        return self.refresh_token

    def get_access_token(self):
        if self.is_expired():
            self.refresh()
        return self.access_token

    def get_sess_key(self):
        response = requests.post(
            'https://api.openai.com/dashboard/onboarding/login',
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
            },
            proxies=self.proxy
        )
        if response.ok:
            data = json.loads(response.text)
            return {
                'sess_key': data['user']['session']['sensitive_id'],
                'created': to_time(data['user']['session']['created']),
                'last_use': to_time(data['user']['session']['last_use']),
            }

    def is_expired(self):
        if not self.access_token:
            return True
        payload = self.access_token.split('.')[1]
        payload = payload + '=' * - (len(payload) % - 4)
        exp = json.loads(base64.b64decode(payload).decode()).get('exp')
        return exp - time.time() < 60

    def refresh(self):
        self.ensure_refresh_token()
        if self.is_expired():
            self.access_token = self.generate_access_token()
        self.save_token()

    def ensure_refresh_token(self):
        if self.refresh_token:
            return
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)
        preauth_cookie = self.get_preauth_cookie()
        url = f'https://auth0.openai.com/authorize' \
              f'?client_id=pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh' \
              f'&audience=https%3A%2F%2Fapi.openai.com%2Fv1' \
              f'&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2Fcom.openai.chat%2Fcallback' \
              f'&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20offline' \
              f'&response_type=code' \
              f'&code_challenge={code_challenge}' \
              f'&code_challenge_method=S256' \
              f'&preauth_cookie={preauth_cookie}'

        url += '&prompt=login'
        # print(url)
        # code = input('code: ')
        page = WebPage(chromium_options=self.co)
        page.get(url)
        page.listen.start('com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback')
        res = page.listen.wait()
        code = res.url.split('code=')[1]
        page.close()
        resp_json = requests.post('https://auth0.openai.com/oauth/token', json={
            'redirect_uri': 'com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback',
            'grant_type': 'authorization_code',
            'client_id': 'pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh',
            'code': code,
            'code_verifier': code_verifier
        }, proxies=self.proxy).json()
        # print(json.dumps(resp_json, indent=2))
        self.refresh_token = resp_json.get('refresh_token')
        self.access_token = resp_json.get('access_token')
        # self.id_token = resp_json.get('id_token')

    def revoke_refresh_token(self, refresh_token):
        resp = requests.post('https://auth0.openai.com/oauth/revoke', json={
            'client_id': 'pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh',
            'token': refresh_token
        }, proxies=self.proxy)
        assert resp.status_code == 200

    @staticmethod
    def generate_code_verifier():
        return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')

    @staticmethod
    def generate_code_challenge(code_verifier):
        m = hashlib.sha256()
        m.update(code_verifier.encode())
        return base64.urlsafe_b64encode(m.digest()).decode().rstrip('=')

    @staticmethod
    def get_preauth_cookie():
        # fakeopen已挂
        # return requests.get('https://ai.fakeopen.com/auth/preauth').json().get('preauth_cookie')
        return requests.get('https://xq6174.serv00.net/preauth.php').json().get('preauth_cookie')

    def generate_access_token(self):
        resp = requests.post('https://token.oaifree.com/api/auth/refresh', data={
            'refresh_token': self.refresh_token
        })
        if resp.status_code == 200:
            return resp.json().get('access_token')
        else:
            return self.generate_access_token_old()

    def generate_access_token_old(self):
        resp = requests.post(
            'https://auth0.openai.com/oauth/token',
            json={
                'redirect_uri': 'com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback',
                'grant_type': 'refresh_token',
                'client_id': 'pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh',
                'refresh_token': self.refresh_token
            },
            headers={'Content-Type': 'application/json'},
            proxies=self.proxy)
        if resp.status_code == 200:
            return resp.json().get('access_token')

    def load_token(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as file:
                token_json = json.load(file)
                if not self.access_token:
                    self.access_token = token_json.get('access_token')
                if not self.refresh_token:
                    self.refresh_token = token_json.get('refresh_token')

    def save_token(self):
        if not self.access_token:
            return
        with open(self.storage_path, 'w') as file:
            json.dump({'refresh_token': self.refresh_token, 'access_token': self.access_token}, file, indent=2)


@click.command()
@click.option('--proxy', "-p", help='A http proxy str. (http://127.0.0.1:8080)', required=False)
@click.option("--refresh_token", "-r", help='Get refresh token.', is_flag=True)
@click.option("--access_token", "-a", help='Get access token.', is_flag=True)
@click.option("--sess_key", "-s", help='Get sess key.', is_flag=True)
def cli(proxy, refresh_token, access_token, sess_key):
    obj = TokenManager(proxy=proxy)
    if refresh_token:
        print("refresh_token: ", obj.get_refresh_token())
    if access_token:
        _access_token = obj.get_access_token()
        payload = _access_token.split('.')[1]
        payload = payload + '=' * - (len(payload) % - 4)
        exp = json.loads(base64.b64decode(payload).decode()).get('exp')
        print({"access_token": obj.get_access_token(), 'expired': to_time(exp)})
    if sess_key:
        print(obj.get_sess_key())


if __name__ == '__main__':
    cli()
