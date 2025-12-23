import logging
import shutil
import uuid
import jwt
import base64
import hmac
import hashlib
import requests
import os
import bcrypt

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import json


from datetime import datetime, timedelta
import pytz
from pytz import UTC
from typing import Optional, Union, List, Dict

from opentelemetry import trace

from open_webui.config import WEBUI_URL
from open_webui.utils.smtp import send_email

from open_webui.utils.access_control import has_permission
from open_webui.models.users import Users

from open_webui.constants import ERROR_MESSAGES

from open_webui.env import (
    ENABLE_PASSWORD_VALIDATION,
    OFFLINE_MODE,
    LICENSE_BLOB,
    PASSWORD_VALIDATION_REGEX_PATTERN,
    REDIS_KEY_PREFIX,
    pk,
    WEBUI_SECRET_KEY,
    TRUSTED_SIGNATURE_KEY,
    STATIC_DIR,
    WEBUI_AUTH_TRUSTED_EMAIL_HEADER,
    FRONTEND_BUILD_DIR,
    REDIS_URL,
    REDIS_SENTINEL_HOSTS,
    REDIS_SENTINEL_PORT,
    WEBUI_NAME,
    REDIS_CLUSTER,
)

from fastapi import BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from open_webui.utils.redis import get_redis_connection, get_sentinels_from_env

log = logging.getLogger(__name__)

SESSION_SECRET = WEBUI_SECRET_KEY
ALGORITHM = "HS256"


##############
# Auth Utils
##############


def verify_signature(payload: str, signature: str) -> bool:
    """
    Verifies the HMAC signature of the received payload.
    """
    try:
        expected_signature = base64.b64encode(
            hmac.new(TRUSTED_SIGNATURE_KEY, payload.encode(), hashlib.sha256).digest()
        ).decode()

        # Compare securely to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)

    except Exception:
        return False


def override_static(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    r = requests.get(content, stream=True)
    with open(path, "wb") as f:
        r.raw.decode_content = True
        shutil.copyfileobj(r.raw, f)


def get_license_data(app, key):
    payload = {
        "resources": {
            os.path.join(STATIC_DIR, "logo.png"): os.getenv("CUSTOM_PNG", ""),
            os.path.join(STATIC_DIR, "favicon.png"): os.getenv("CUSTOM_PNG", ""),
            os.path.join(STATIC_DIR, "favicon.svg"): os.getenv("CUSTOM_SVG", ""),
            os.path.join(STATIC_DIR, "favicon-96x96.png"): os.getenv("CUSTOM_PNG", ""),
            os.path.join(STATIC_DIR, "apple-touch-icon.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(STATIC_DIR, "web-app-manifest-192x192.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(STATIC_DIR, "web-app-manifest-512x512.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(STATIC_DIR, "splash.png"): os.getenv("CUSTOM_PNG", ""),
            os.path.join(STATIC_DIR, "favicon.ico"): os.getenv("CUSTOM_ICO", ""),
            os.path.join(STATIC_DIR, "favicon-dark.png"): os.getenv(
                "CUSTOM_DARK_PNG", ""
            ),
            os.path.join(STATIC_DIR, "splash-dark.png"): os.getenv(
                "CUSTOM_DARK_PNG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "favicon.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/favicon.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/favicon.svg"): os.getenv(
                "CUSTOM_SVG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/favicon-96x96.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/apple-touch-icon.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(
                FRONTEND_BUILD_DIR, "static/web-app-manifest-192x192.png"
            ): os.getenv("CUSTOM_PNG", ""),
            os.path.join(
                FRONTEND_BUILD_DIR, "static/web-app-manifest-512x512.png"
            ): os.getenv("CUSTOM_PNG", ""),
            os.path.join(FRONTEND_BUILD_DIR, "static/splash.png"): os.getenv(
                "CUSTOM_PNG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/favicon.ico"): os.getenv(
                "CUSTOM_ICO", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/favicon-dark.png"): os.getenv(
                "CUSTOM_DARK_PNG", ""
            ),
            os.path.join(FRONTEND_BUILD_DIR, "static/splash-dark.png"): os.getenv(
                "CUSTOM_DARK_PNG", ""
            ),
        },
        "metadata": {
            "type": "enterprise",
            "organization_name": os.getenv("ORGANIZATION_NAME", "OpenWebui"),
        },
    }
    try:
        for k, v in payload.items():
            if k == "resources":
                for p, c in v.items():
                    if c:
                        globals().get("override_static", lambda a, b: None)(p, c)
            elif k == "count":
                setattr(app.state, "USER_COUNT", v)
            elif k == "name":
                setattr(app.state, "WEBUI_NAME", v)
            elif k == "metadata":
                setattr(app.state, "LICENSE_METADATA", v)
        return True
    except Exception as ex:
        log.exception(f"License: Uncaught Exception: {ex}")

    return True


bearer_security = HTTPBearer(auto_error=False)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def validate_password(password: str) -> bool:
    # The password passed to bcrypt must be 72 bytes or fewer. If it is longer, it will be truncated before hashing.
    if len(password.encode("utf-8")) > 72:
        raise Exception(
            ERROR_MESSAGES.PASSWORD_TOO_LONG,
        )

    if ENABLE_PASSWORD_VALIDATION:
        if not PASSWORD_VALIDATION_REGEX_PATTERN.match(password):
            raise Exception(ERROR_MESSAGES.INVALID_PASSWORD())

    return True


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return (
        bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
        if hashed_password
        else None
    )


def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
        payload.update({"exp": expire})

    jti = str(uuid.uuid4())
    payload.update({"jti": jti})

    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception:
        return None


async def is_valid_token(request, decoded) -> bool:
    # Require Redis to check revoked tokens
    if request.app.state.redis:
        jti = decoded.get("jti")

        if jti:
            revoked = await request.app.state.redis.get(
                f"{REDIS_KEY_PREFIX}:auth:token:{jti}:revoked"
            )
            if revoked:
                return False

    return True


async def invalidate_token(request, token):
    decoded = decode_token(token)

    # Require Redis to store revoked tokens
    if request.app.state.redis:
        jti = decoded.get("jti")
        exp = decoded.get("exp")

        if jti and exp:
            ttl = exp - int(
                datetime.now(UTC).timestamp()
            )  # Calculate time-to-live for the token

            if ttl > 0:
                # Store the revoked token in Redis with an expiration time
                await request.app.state.redis.set(
                    f"{REDIS_KEY_PREFIX}:auth:token:{jti}:revoked",
                    "1",
                    ex=ttl,
                )


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]


def create_api_key():
    key = str(uuid.uuid4()).replace("-", "")
    return f"sk-{key}"


def get_http_authorization_cred(auth_header: Optional[str]):
    if not auth_header:
        return None
    try:
        scheme, credentials = auth_header.split(" ")
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
    except Exception:
        return None


async def get_current_user(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    token = None

    if auth_token is not None:
        token = auth_token.credentials

    if token is None and "token" in request.cookies:
        token = request.cookies.get("token")

    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # auth by api key
    if token.startswith("sk-"):
        user = get_current_user_by_api_key(request, token)

        # Add user info to current span
        current_span = trace.get_current_span()
        if current_span:
            current_span.set_attribute("client.user.id", user.id)
            current_span.set_attribute("client.user.email", user.email)
            current_span.set_attribute("client.user.role", user.role)
            current_span.set_attribute("client.auth.type", "api_key")

        return user

    # auth by jwt token
    try:
        try:
            data = decode_token(token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

        if data is not None and "id" in data:
            if data.get("jti") and not await is_valid_token(request, data):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                )

            user = Users.get_user_by_id(data["id"])
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=ERROR_MESSAGES.INVALID_TOKEN,
                )
            else:
                if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
                    trusted_email = request.headers.get(
                        WEBUI_AUTH_TRUSTED_EMAIL_HEADER, ""
                    ).lower()
                    if trusted_email and user.email != trusted_email:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User mismatch. Please sign in again.",
                        )

                # Add user info to current span
                current_span = trace.get_current_span()
                if current_span:
                    current_span.set_attribute("client.user.id", user.id)
                    current_span.set_attribute("client.user.email", user.email)
                    current_span.set_attribute("client.user.role", user.role)
                    current_span.set_attribute("client.auth.type", "jwt")

                # Refresh the user's last active timestamp asynchronously
                # to prevent blocking the request
                if background_tasks:
                    background_tasks.add_task(Users.update_last_active_by_id, user.id)
            return user
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.UNAUTHORIZED,
            )
    except Exception as e:
        # Delete the token cookie
        if request.cookies.get("token"):
            response.delete_cookie("token")

        if request.cookies.get("oauth_id_token"):
            response.delete_cookie("oauth_id_token")

        # Delete OAuth session if present
        if request.cookies.get("oauth_session_id"):
            response.delete_cookie("oauth_session_id")

        raise e


def get_current_user_by_api_key(request, api_key: str):
    user = Users.get_user_by_api_key(api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )

    if not request.state.enable_api_keys or (
        user.role != "admin"
        and not has_permission(
            user.id,
            "features.api_keys",
            request.app.state.config.USER_PERMISSIONS,
        )
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED
        )

    # Add user info to current span
    current_span = trace.get_current_span()
    if current_span:
        current_span.set_attribute("client.user.id", user.id)
        current_span.set_attribute("client.user.email", user.email)
        current_span.set_attribute("client.user.role", user.role)
        current_span.set_attribute("client.auth.type", "api_key")

    Users.update_last_active_by_id(user.id)
    return user


def get_verified_user(user=Depends(get_current_user)):
    if user.role not in {"user", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


def get_admin_user(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


verify_email_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%(title)s</title>
    <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f6f8; margin: 0; padding: 0; -webkit-text-size-adjust: 100%%; }
        .container { max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
        /* 黑色背景以融合黑色Logo */
        .header { background-color: #000000; padding: 40px 20px; text-align: center; }
        .logo-img { max-width: 150px; height: auto; display: block; margin: 0 auto; }
        .content { padding: 40px 40px; text-align: left; }
        .content h2 { color: #1a1a1a; margin-top: 0; margin-bottom: 20px; font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
        .content p { color: #555555; line-height: 1.7; margin: 0 0 20px; font-size: 16px; }
        .btn-container { text-align: center; margin: 35px 0; }
        /* 按钮使用醒目的蓝色，与黑色背景形成对比 */
        .button { display: inline-block; background-color: #007bff; color: #ffffff !important; text-decoration: none; padding: 14px 36px; border-radius: 8px; font-weight: 600; font-size: 16px; transition: background-color 0.3s; box-shadow: 0 4px 6px rgba(0, 123, 255, 0.2); }
        .button:hover { background-color: #0056b3; }
        .link-box { background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 15px; border-radius: 6px; font-family: Monaco, Consolas, monospace; font-size: 13px; color: #666; word-break: break-all; margin-top: 20px; }
        .footer { background-color: #f8f9fa; color: #999999; text-align: center; padding: 30px 20px; font-size: 13px; border-top: 1px solid #eeeeee; }
        .footer p { margin: 5px 0; }
        
        @media only screen and (max-width: 600px) {
            .container { margin: 0; border-radius: 0; width: 100%%; }
            .content { padding: 30px 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <!-- 使用提供的黑色背景Logo -->
            <img src="https://img.comiai.cc/file/1766468774804_64a473739b885d30233514a315446bfb.png" alt="Logo" class="logo-img">
        </div>
        <div class="content">
            <h2>验证您的电子邮箱</h2>
            <p>您好！感谢您注册我们的服务。</p>
            <p>为了保障您的账户安全并完成注册流程，我们需要确认这是您的电子邮箱地址。请点击下方按钮进行验证：</p>
            
            <div class="btn-container">
                <a href="%(link)s" class="button" target="_blank">立即验证邮箱</a>
            </div>

            <p style="font-size: 14px; color: #888;">链接将在 24 小时后失效。如果您并未发起此注册，请直接忽略此邮件。</p>

            <div style="margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px;">
                <p style="font-size: 14px; margin-bottom: 10px;">如果按钮无法点击，请复制以下链接到浏览器地址栏：</p>
                <div class="link-box">%(link)s</div>
            </div>
        </div>
        <div class="footer">
            <p>&copy; Comi AI. All rights reserved.</p>
            <p>此邮件由系统自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>
"""


password_reset_email_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%(title)s</title>
    <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f6f8; margin: 0; padding: 0; -webkit-text-size-adjust: 100%%; }
        .container { max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
        /* 黑色背景以融合黑色Logo */
        .header { background-color: #000000; padding: 40px 20px; text-align: center; }
        .logo-img { max-width: 150px; height: auto; display: block; margin: 0 auto; }
        .content { padding: 40px 40px; text-align: left; }
        .content h2 { color: #1a1a1a; margin-top: 0; margin-bottom: 20px; font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
        .content p { color: #555555; line-height: 1.7; margin: 0 0 20px; font-size: 16px; }
        .btn-container { text-align: center; margin: 35px 0; }
        /* 红色/橙色按钮用于重置密码，暗示安全/重要性 */
        .button { display: inline-block; background-color: #e63946; color: #ffffff !important; text-decoration: none; padding: 14px 36px; border-radius: 8px; font-weight: 600; font-size: 16px; transition: background-color 0.3s; box-shadow: 0 4px 6px rgba(230, 57, 70, 0.2); }
        .button:hover { background-color: #c92a37; }
        .warning-box { background-color: #fff8e1; border-left: 4px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 4px; color: #856404; font-size: 14px; }
        .link-box { background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 15px; border-radius: 6px; font-family: Monaco, Consolas, monospace; font-size: 13px; color: #666; word-break: break-all; margin-top: 20px; }
        .footer { background-color: #f8f9fa; color: #999999; text-align: center; padding: 30px 20px; font-size: 13px; border-top: 1px solid #eeeeee; }
        .footer p { margin: 5px 0; }

        @media only screen and (max-width: 600px) {
            .container { margin: 0; border-radius: 0; width: 100%%; }
            .content { padding: 30px 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="https://img.comiai.cc/file/1766468774804_64a473739b885d30233514a315446bfb.png" alt="Logo" class="logo-img">
        </div>
        <div class="content">
            <h2>重置您的密码</h2>
            <p>您好！我们刚刚收到了重置您账户密码的请求。</p>
            <p>如果是您本人的操作，请点击下方按钮设置新密码：</p>
            
            <div class="btn-container">
                <a href="%(link)s" class="button" target="_blank">重置密码</a>
            </div>

            <div class="warning-box">
                <strong>重要提醒：</strong>
                <ul style="margin: 5px 0 0 20px; padding: 0;">
                    <li>此链接将在 1 小时后失效。</li>
                    <li>为了账户安全，请勿将此链接转发给他人。</li>
                    <li>如果您没有请求重置密码，请忽略此邮件，您的账户依然安全。</li>
                </ul>
            </div>

            <div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
                <p style="font-size: 14px; margin-bottom: 10px;">如果按钮无法点击，请复制以下链接到浏览器地址栏：</p>
                <div class="link-box">%(link)s</div>
            </div>
        </div>
        <div class="footer">
            <p>&copy; Comi AI. All rights reserved.</p>
            <p>此邮件由系统自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>
"""


def get_email_code_key(code: str) -> str:
    return f"email_verify:{code}"


def get_password_reset_key(code: str) -> str:
    return f"password_reset:{code}"


def send_verify_email(email: str):
    redis = get_redis_connection(
        redis_url=REDIS_URL,
        redis_sentinels=get_sentinels_from_env(
            REDIS_SENTINEL_HOSTS, REDIS_SENTINEL_PORT
        ),
        redis_cluster=REDIS_CLUSTER,
    )
    code = f"{uuid.uuid4().hex}{uuid.uuid1().hex}"
    redis.set(name=get_email_code_key(code=code), value=email, ex=timedelta(days=1))
    link = f"{WEBUI_URL.value.rstrip('/')}/api/v1/auths/signup_verify/{code}"
    send_email(
        receiver=email,
        subject=f"Comi AI 邮箱验证",
        body=verify_email_template
        % {"title": f"Comi AI 邮箱验证", "link": link},
    )


def send_password_reset_email(email: str):
    redis = get_redis_connection(
        redis_url=REDIS_URL,
        redis_sentinels=get_sentinels_from_env(
            REDIS_SENTINEL_HOSTS, REDIS_SENTINEL_PORT
        ),
    )
    code = f"{uuid.uuid4().hex}{uuid.uuid1().hex}"
    redis.set(name=get_password_reset_key(code=code), value=email, ex=timedelta(hours=1))
    link = f"{WEBUI_URL.value.rstrip('/')}/auth/reset-password?token={code}"
    send_email(
        receiver=email,
        subject=f"重置您的密码 - {WEBUI_NAME}",
        body=password_reset_email_template
        % {"title": f"重置您的密码 - {WEBUI_NAME}", "link": link},
    )


def verify_password_reset_token(token: str) -> str:
    redis = get_redis_connection(
        redis_url=REDIS_URL,
        redis_sentinels=get_sentinels_from_env(
            REDIS_SENTINEL_HOSTS, REDIS_SENTINEL_PORT
        ),
    )
    email = redis.get(name=get_password_reset_key(code=token))
    if email:
        # 用完即删除token
        redis.delete(get_password_reset_key(code=token))
    return email


def verify_email_by_code(code: str) -> str:
    redis = get_redis_connection(
        redis_url=REDIS_URL,
        redis_sentinels=get_sentinels_from_env(
            REDIS_SENTINEL_HOSTS, REDIS_SENTINEL_PORT
        ),
        redis_cluster=REDIS_CLUSTER,
    )
    return redis.get(name=get_email_code_key(code=code))


async def verify_recaptcha(token: str, secret_key: str) -> bool:
    """
    验证reCAPTCHA令牌
    """
    if not token or not secret_key:
        return False
        
    try:
        data = {
            'secret': secret_key,
            'response': token
        }
        
        response = requests.post(
            'https://www.recaptcha.net/recaptcha/api/siteverify',
            data=data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get('success', False)
        
    except Exception as e:
        log.error(f"reCAPTCHA验证失败: {str(e)}")
        
    return False
