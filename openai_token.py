import base64
import hashlib
import json
import os
import random
import ssl
import string
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import click
import httpx
from DrissionPage import ChromiumOptions
from DrissionPage._pages.web_page import WebPage


DEFAULT_PROXY = "http://127.0.0.1:10808"
DEFAULT_STORAGE_PATH = Path("./tokens.json")


def to_time(value=None):
    if value is None:
        value = time.time()
    if isinstance(value, str):
        return value
    if value > 10**12:
        value = value / 1000
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def emit(payload):
    click.echo(json.dumps(payload, indent=2, ensure_ascii=False))


def decode_jwt_payload(token):
    if not token:
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())


def build_ssl_context(ca_bundle=None):
    cafile = str(ca_bundle) if ca_bundle else None
    return ssl.create_default_context(cafile=cafile)


class TokenStore:
    def __init__(self, storage_path):
        self.storage_path = Path(storage_path)
        self.loaded_from_legacy = False
        self.data = self._load()

    def _default_data(self):
        return {
            "version": 2,
            "default_account": None,
            "accounts": {},
        }

    def _guess_legacy_account_name(self):
        stem = self.storage_path.stem.strip()
        if stem and stem.lower() not in {"token", "tokens"}:
            return stem
        return "default"

    def _normalize_sess_key(self, value):
        if not value:
            return None
        if isinstance(value, str):
            return {
                "sess_key": value,
                "created": None,
                "last_use": None,
            }
        if isinstance(value, dict):
            sess_key = value.get("sess_key") or value.get("sensitive_id")
            if not sess_key:
                return None
            return {
                "sess_key": sess_key,
                "created": to_time(value.get("created")),
                "last_use": to_time(value.get("last_use")),
            }
        return None

    def _normalize_account(self, payload):
        payload = payload or {}
        return {
            "device_token": payload.get("device_token"),
            "refresh_token": payload.get("refresh_token"),
            "access_token": payload.get("access_token"),
            "sess_key": self._normalize_sess_key(payload.get("sess_key")),
            "updated_at": payload.get("updated_at"),
        }

    def _load(self):
        if not self.storage_path.exists():
            return self._default_data()

        with self.storage_path.open("r", encoding="utf-8") as file:
            raw = json.load(file)

        if isinstance(raw, dict) and "accounts" in raw:
            data = self._default_data()
            data["version"] = raw.get("version", 2)
            data["default_account"] = raw.get("default_account")
            data["accounts"] = {
                name: self._normalize_account(account)
                for name, account in raw.get("accounts", {}).items()
            }
            if not data["default_account"] and data["accounts"]:
                data["default_account"] = sorted(data["accounts"])[0]
            return data

        if isinstance(raw, dict):
            self.loaded_from_legacy = True
            account_name = self._guess_legacy_account_name()
            data = self._default_data()
            data["default_account"] = account_name
            data["accounts"][account_name] = self._normalize_account(raw)
            return data

        raise click.ClickException(f"无法解析存储文件: {self.storage_path}")

    def save(self):
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self.storage_path.open("w", encoding="utf-8") as file:
            json.dump(self.data, file, indent=2, ensure_ascii=False)

    def resolve_account_name(self, requested=None):
        if requested:
            return requested
        if self.data["default_account"]:
            return self.data["default_account"]
        accounts = sorted(self.data["accounts"])
        if len(accounts) == 1:
            return accounts[0]
        return None

    def get_account(self, account_name, create=False):
        account = self.data["accounts"].get(account_name)
        if account is None and create:
            account = self._normalize_account({})
            self.data["accounts"][account_name] = account
        return account

    def update_account(self, account_name, payload, set_default=False):
        account = self.get_account(account_name, create=True)
        account.update(payload)
        account["updated_at"] = to_time()
        if set_default or not self.data["default_account"]:
            self.data["default_account"] = account_name
        self.save()
        return account

    def remove_account(self, account_name):
        if account_name not in self.data["accounts"]:
            return False
        del self.data["accounts"][account_name]
        if self.data["default_account"] == account_name:
            remaining = sorted(self.data["accounts"])
            self.data["default_account"] = remaining[0] if remaining else None
        self.save()
        return True

    def set_default_account(self, account_name):
        if account_name not in self.data["accounts"]:
            raise click.ClickException(f"账号不存在: {account_name}")
        self.data["default_account"] = account_name
        self.save()

    def adopt_legacy_account_name(self, account_name):
        if not self.loaded_from_legacy:
            return
        current_accounts = sorted(self.data["accounts"])
        if len(current_accounts) != 1:
            return
        current_name = current_accounts[0]
        if current_name == account_name:
            return
        self.data["accounts"][account_name] = self.data["accounts"].pop(current_name)
        if self.data["default_account"] == current_name:
            self.data["default_account"] = account_name
        self.loaded_from_legacy = False
        self.save()

    def list_accounts(self):
        summaries = []
        default_account = self.data["default_account"]
        for account_name in sorted(self.data["accounts"]):
            account = self.data["accounts"][account_name]
            sess_key = account.get("sess_key") or {}
            summaries.append(
                {
                    "account": account_name,
                    "is_default": account_name == default_account,
                    "has_device_token": bool(account.get("device_token")),
                    "has_refresh_token": bool(account.get("refresh_token")),
                    "has_access_token": bool(account.get("access_token")),
                    "has_sess_key": bool(sess_key.get("sess_key")),
                    "sess_last_use": sess_key.get("last_use"),
                    "updated_at": account.get("updated_at"),
                }
            )
        return summaries


class TokenManager:
    def __init__(
        self,
        store,
        account_name,
        refresh_token=None,
        device_token=None,
        storage_path=DEFAULT_STORAGE_PATH,
        proxy=DEFAULT_PROXY,
        ca_bundle=None,
    ):
        self.store = store
        self.account_name = account_name
        self.storage_path = Path(storage_path)
        self.refresh_token = refresh_token
        self.device_token = device_token
        self.access_token = None
        self.sess_key = None
        self.co = ChromiumOptions()

        if proxy:
            self.co.set_proxy(proxy)

        self.client = httpx.Client(
            proxy=proxy,
            verify=build_ssl_context(ca_bundle),
            follow_redirects=True,
            timeout=httpx.Timeout(30.0, connect=30.0),
        )
        self.load_token()
        self.save_token()

    def close(self):
        self.client.close()

    def load_token(self):
        token_json = self.store.get_account(self.account_name, create=True) or {}
        if not self.access_token:
            self.access_token = token_json.get("access_token")
        if not self.refresh_token:
            self.refresh_token = token_json.get("refresh_token")
        if not self.device_token:
            self.device_token = token_json.get("device_token")
        self.sess_key = token_json.get("sess_key")

    def save_token(self):
        self.store.update_account(
            self.account_name,
            {
                "device_token": self.device_token,
                "refresh_token": self.refresh_token,
                "access_token": self.access_token,
                "sess_key": self.sess_key,
            },
        )

    def get_refresh_token(self):
        self.ensure_refresh_token()
        return self.refresh_token

    def get_access_token(self):
        if self.is_expired():
            self.refresh()
        return self.access_token

    def get_sess_key(self):
        response = self.client.post(
            "https://api.openai.com/dashboard/onboarding/login",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0"
                ),
            },
        )
        response.raise_for_status()
        sess_key = self.extract_sess_key(response.json())
        if not sess_key:
            raise click.ClickException("接口返回中未找到 sess_key")
        self.sess_key = sess_key
        self.save_token()
        return sess_key

    @staticmethod
    def extract_sess_key(payload):
        if payload.get("sess_key"):
            return {
                "sess_key": payload.get("sess_key"),
                "created": to_time(payload.get("created")),
                "last_use": to_time(payload.get("last_use")),
            }

        session = payload.get("user", {}).get("session", {})
        if not session:
            return None

        sess_key = session.get("sensitive_id") or session.get("sess_key")
        if not sess_key:
            return None

        return {
            "sess_key": sess_key,
            "created": to_time(session.get("created")),
            "last_use": to_time(session.get("last_use")),
        }

    def is_expired(self):
        if not self.access_token:
            return True
        exp = decode_jwt_payload(self.access_token).get("exp")
        if not exp:
            return True
        return exp - time.time() < 60

    def refresh(self):
        self.ensure_refresh_token()
        self.access_token = self.generate_access_token()
        self.save_token()

    def login(self):
        self.ensure_refresh_token(force_login=True)
        if self.access_token:
            self.save_token()
        return self.store.get_account(self.account_name)

    def ensure_refresh_token(self, force_login=False):
        if self.refresh_token and not force_login:
            return

        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)
        preauth_cookie = self.get_preauth_cookie()
        if not preauth_cookie:
            raise click.ClickException("获取 preauth_cookie 失败")

        url = (
            "https://auth.openai.com/api/accounts/authorize"
            "?scope=openid%20email%20profile%20offline_access%20model.request%20"
            "model.read%20organization.read%20organization.write"
            "&prompt=login"
            "&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2F"
            "com.openai.chat%2Fcallback"
            f"&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
            "&client_id=app_WXrF1LSkiTtfYqiL6XtjygvX"
            "&state=xxxxxxx-XXHRvckQ-8ti7hV96faOTk80YTKKMz6LcMc"
            "&response_type=code"
            f"&preauth_cookie={preauth_cookie}"
            "&audience=https%3A%2F%2Fapi.openai.com%2Fv1"
        )

        page = WebPage(chromium_options=self.co)
        try:
            page.get(url)
            page.listen.start(
                "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback"
            )
            result = page.listen.wait()
        finally:
            page.close()

        query = dict(parse_qsl(urlparse(result.url).query))
        code = query.get("code")
        if not code:
            raise click.ClickException("登录完成后未拿到授权 code，preauth_cookie 可能已过期")

        resp_json = self.client.post(
            "https://auth0.openai.com/oauth/token",
            json={
                "redirect_uri": (
                    "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback"
                ),
                "grant_type": "authorization_code",
                "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
                "code": code,
                "code_verifier": code_verifier,
            },
        )
        resp_json.raise_for_status()
        token_payload = resp_json.json()
        self.refresh_token = token_payload.get("refresh_token")
        self.access_token = token_payload.get("access_token")
        if not self.refresh_token:
            raise click.ClickException("登录成功但没有返回 refresh_token")
        self.save_token()

    def revoke_refresh_token(self, refresh_token):
        resp = self.client.post(
            "https://auth0.openai.com/oauth/revoke",
            json={
                "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
                "token": refresh_token,
            },
        )
        resp.raise_for_status()
        self.refresh_token = None
        self.access_token = None
        self.save_token()

    @staticmethod
    def generate_code_verifier():
        return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

    @staticmethod
    def generate_code_challenge(code_verifier):
        digest = hashlib.sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def get_preauth_cookie(self):
        if self.device_token:
            rsp = self.client.post(
                "https://ios.chat.openai.com/backend-api/preauth_devicecheck",
                json={
                    "bundle_id": "com.openai.chat",
                    "device_id": "62345678-042E-45C7-962F-AC725D0E7770",
                    "device_token": self.device_token,
                    "request_flag": True,
                },
            )
            if rsp.status_code == 200 and rsp.json().get("is_ok"):
                cookie = rsp.cookies.get("_preauth_devicecheck")
                if cookie:
                    return cookie


    def generate_access_token(self):
        self.ensure_refresh_token()
        return self.generate_access_token_old()

    def generate_share_token(self, unique_name="share_token"):
        resp = self.client.post(
            "https://chat.oaifree.com/token/register",
            data={
                "unique_name": unique_name,
                "access_token": self.get_access_token(),
                "expires_in": 20,
                "site_limit": None,
                "gpt35_limit": -1,
                "gpt4_limit": -1,
                "show_conversations": True,
                "show_userinfo": False,
                "reset_limit": True,
            },
        )
        resp.raise_for_status()
        return resp.json().get("token_key")

    def generate_access_token_old(self):
        resp = self.client.post(
            "https://auth0.openai.com/oauth/token",
            json={
                "redirect_uri": (
                    "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback"
                ),
                "grant_type": "refresh_token",
                "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
                "refresh_token": self.refresh_token,
            },
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            payload = resp.json()
            self.access_token = payload.get("access_token")
            self.refresh_token = payload.get("refresh_token")
            self.save_token()
            return self.access_token

        self.refresh_token = None
        self.access_token = None
        self.save_token()
        raise click.ClickException(
            f"获取 access_token 失败: {resp.status_code} {resp.text}"
        )


@click.command()
@click.option(
    "--proxy",
    "-p",
    default=DEFAULT_PROXY,
    show_default=True,
    help="HTTP proxy, example: http://127.0.0.1:8080",
)
@click.option(
    "--storage-path",
    default=str(DEFAULT_STORAGE_PATH),
    show_default=True,
    help="Token storage file.",
)
@click.option("--account", "-A", help="Account alias in the storage file.")
@click.option("--device-token", help="Override device_token for the selected account.")
@click.option(
    "--ca-bundle",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Custom CA bundle path for HTTPS verification.",
)
@click.option("--login", "-N", is_flag=True, help="Trigger browser login and save tokens.")
@click.option("--list-accounts", "-L", is_flag=True, help="List all managed accounts.")
@click.option("--set-default", "-D", is_flag=True, help="Set the selected account as default.")
@click.option("--remove-account", "-R", is_flag=True, help="Remove the selected account.")
@click.option(
    "--refresh-token",
    "--refresh_token",
    "-r",
    "show_refresh_token",
    is_flag=True,
    help="Get refresh token.",
)
@click.option(
    "--access-token",
    "--access_token",
    "-a",
    "show_access_token",
    is_flag=True,
    help="Get access token.",
)
@click.option(
    "--sess-key",
    "--sess_key",
    "-s",
    "show_sess_key",
    is_flag=True,
    help="Get sess key and persist it.",
)
@click.option(
    "--share-token",
    "--share_token",
    "-f",
    "show_share_token",
    is_flag=True,
    help="Get share key.",
)
@click.pass_context
def cli(
    ctx,
    proxy,
    storage_path,
    account,
    device_token,
    ca_bundle,
    login,
    list_accounts,
    set_default,
    remove_account,
    show_refresh_token,
    show_access_token,
    show_sess_key,
    show_share_token,
):
    store = TokenStore(storage_path)

    if list_accounts:
        emit(
            {
                "storage_path": str(Path(storage_path).resolve()),
                "default_account": store.data["default_account"],
                "accounts": store.list_accounts(),
            }
        )
        return

    account_name = store.resolve_account_name(account)
    if not account_name:
        fallback_name = Path(storage_path).stem
        account_name = fallback_name if fallback_name.lower() not in {"token", "tokens"} else "default"
    if account:
        store.adopt_legacy_account_name(account_name)

    if remove_account:
        removed = store.remove_account(account_name)
        emit(
            {
                "account": account_name,
                "removed": removed,
                "default_account": store.data["default_account"],
            }
        )
        return

    manager = TokenManager(
        store=store,
        account_name=account_name,
        device_token=device_token,
        storage_path=storage_path,
        proxy=proxy,
        ca_bundle=ca_bundle,
    )

    try:
        if set_default:
            store.set_default_account(account_name)

        performed = set_default

        if login:
            manager.login()
            emit(
                {
                    "account": account_name,
                    "status": "logged_in",
                    "saved": store.get_account(account_name),
                }
            )
            performed = True

        if show_refresh_token:
            emit({"account": account_name, "refresh_token": manager.get_refresh_token()})
            performed = True

        if show_access_token:
            access_token = manager.get_access_token()
            exp = decode_jwt_payload(access_token).get("exp")
            emit(
                {
                    "account": account_name,
                    "access_token": access_token,
                    "expired": to_time(exp) if exp else None,
                }
            )
            performed = True

        if show_sess_key:
            emit({"account": account_name, **manager.get_sess_key()})
            performed = True

        if show_share_token:
            unique_name = "".join(
                random.sample(string.ascii_letters + string.digits, 16)
            )
            emit(
                {
                    "account": account_name,
                    "share_token": manager.generate_share_token(unique_name),
                    "unique_name": unique_name,
                }
            )
            performed = True

        if not performed:
            click.echo(ctx.get_help())
    finally:
        manager.close()


if __name__ == "__main__":
    cli()
