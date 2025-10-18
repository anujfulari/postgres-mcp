from __future__ import annotations

# pyright: reportMissingImports=false, reportUntypedFunctionDecorator=false

import asyncio
import base64
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import Optional

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from jose import jwt
from pydantic import BaseModel
from starlette.requests import Request
from urllib.parse import parse_qs

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except Exception as exc:  # noqa: BLE001 - optional import error will surface at runtime
    raise

logger = logging.getLogger(__name__)


def _b64url_uint(val: int) -> str:
    data = val.to_bytes((val.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _now() -> int:
    return int(time.time())


@dataclass
class Client:
    client_id: str
    client_secret: str
    scopes: list[str]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    scope: str = ""


class EmbeddedOAuthServer:
    """Minimal embedded OAuth2 server supporting client_credentials and JWKS (RS256)."""

    def __init__(
        self,
        host: str,
        port: int,
        audience: str,
        default_scopes: Optional[list[str]] = None,
        clients: Optional[dict[str, Client]] = None,
        issuer_override: Optional[str] = None,
        token_ttl_seconds: int = 3600,
    ) -> None:
        self.host = host
        self.port = port
        self._audience = audience
        self._default_scopes = default_scopes or []
        self._clients: dict[str, Client] = clients or {}
        self._token_ttl_seconds = token_ttl_seconds

        # Generate an ephemeral RSA keypair (on restart, keys rotate)
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = self._private_key.public_key()
        pub_numbers = public_key.public_numbers()
        self._jwk: Dict[str, Any] = {
            "kty": "RSA",
            "n": _b64url_uint(pub_numbers.n),
            "e": _b64url_uint(pub_numbers.e),
            "alg": "RS256",
            "use": "sig",
            "kid": secrets.token_hex(8),
        }

        # App and routes
        self._app = FastAPI()
        self._issuer = issuer_override or f"http://{self.host}:{self.port}"
        self._install_routes()

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def jwks_url(self) -> str:
        return f"{self._issuer}/.well-known/jwks.json"

    def _install_routes(self) -> None:
        @self._app.get("/health")
        async def health() -> Dict[str, str]:  # noqa: D401 - trivial
            return {"status": "ok"}

        @self._app.get("/.well-known/jwks.json")
        async def jwks() -> Dict[str, Any]:
            return {"keys": [self._jwk]}

        @self._app.get("/.well-known/openid-configuration")
        async def openid_config() -> Dict[str, Any]:
            return {
                "issuer": self._issuer,
                "jwks_uri": f"{self._issuer}/.well-known/jwks.json",
                "token_endpoint": f"{self._issuer}/oauth/token",
                "grant_types_supported": ["client_credentials"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "scopes_supported": self._default_scopes,
            }

        @self._app.get("/.well-known/oauth-authorization-server")
        async def rfc8414_config() -> Dict[str, Any]:
            return {
                "issuer": self._issuer,
                "jwks_uri": f"{self._issuer}/.well-known/jwks.json",
                "token_endpoint": f"{self._issuer}/oauth/token",
                "grant_types_supported": ["client_credentials"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "scopes_supported": self._default_scopes,
            }

        @self._app.post("/oauth/token", response_model=TokenResponse)
        async def token(request: Request) -> Any:
            # Manually parse application/x-www-form-urlencoded or JSON to avoid python-multipart dependency
            content_type = request.headers.get("content-type", "")
            raw_body = await request.body()
            params: Dict[str, str] = {}
            if "application/x-www-form-urlencoded" in content_type:
                parsed = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
                params = {k: v[0] for k, v in parsed.items() if isinstance(v, list) and len(v) > 0}
            else:
                try:
                    data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                    if isinstance(data, dict):
                        params = {k: str(v) for k, v in data.items()}
                except Exception:
                    params = {}

            grant_type = params.get("grant_type")
            client_id = params.get("client_id")
            client_secret = params.get("client_secret")
            scope = params.get("scope")

            if grant_type != "client_credentials":
                raise HTTPException(status_code=400, detail="unsupported_grant_type")

            if not client_id or not client_secret:
                raise HTTPException(status_code=400, detail="invalid_client")

            client = self._clients.get(client_id)
            if not client or client.client_secret != client_secret:
                raise HTTPException(status_code=401, detail="invalid_client")

            requested_scopes = [s for s in (scope or "").split(" ") if s]
            if requested_scopes:
                # Allow subset of client's configured scopes
                invalid = [s for s in requested_scopes if s not in client.scopes]
                if invalid:
                    raise HTTPException(status_code=400, detail=f"invalid_scope: {' '.join(invalid)}")
                final_scopes = requested_scopes
            else:
                final_scopes = client.scopes or self._default_scopes

            now = _now()
            claims = {
                "iss": self._issuer,
                "aud": self._audience,
                "iat": now,
                "nbf": now,
                "exp": now + self._token_ttl_seconds,
                "scope": " ".join(final_scopes) if final_scopes else "",
            }

            private_pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            headers = {"kid": self._jwk["kid"], "alg": "RS256", "typ": "JWT"}
            token = jwt.encode(claims, private_pem, algorithm="RS256", headers=headers)
            return TokenResponse(access_token=token, scope=claims["scope"])  # type: ignore[return-value]

    async def serve(self) -> None:
        import uvicorn

        config = uvicorn.Config(self._app, host=self.host, port=self.port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()

    def add_client(self, client_id: str, client_secret: str, scopes: Optional[list[str]] = None) -> None:
        self._clients[client_id] = Client(client_id=client_id, client_secret=client_secret, scopes=scopes or [])

    @staticmethod
    def from_env_or_args(
        host: str,
        port: int,
        audience: str,
        default_scopes_csv: Optional[str],
        client_id: Optional[str],
        client_secret: Optional[str],
        issuer_override: Optional[str] = None,
    ) -> "EmbeddedOAuthServer":
        default_scopes = [s.strip() for s in (default_scopes_csv or "").split(",") if s and s.strip()]
        server = EmbeddedOAuthServer(
            host=host,
            port=port,
            audience=audience,
            default_scopes=default_scopes,
            issuer_override=issuer_override,
        )

        cid = client_id or secrets.token_urlsafe(12)
        csecret = client_secret or secrets.token_urlsafe(24)
        server.add_client(cid, csecret, scopes=default_scopes)

        # Log credentials once for operator convenience
        logger.info("Embedded OAuth client registered")
        logger.info("  client_id=%s", cid)
        logger.info("  client_secret=%s", csecret)
        if default_scopes:
            logger.info("  scopes=%s", ",".join(default_scopes))

        return server


