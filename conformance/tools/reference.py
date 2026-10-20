"""参考实现：严格按 spec/token-validation.md 与 spec/authorization.md 编写。

它只用于证明测试向量与规范自洽，以及作为三端 SDK 实现时的对照，**不是生产代码**。
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Callable

from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ALLOWED_ALGS = {"RS256": ("RSA", None), "ES256": ("EC", "P-256")}
ACCEPTED_TYP = {"at+jwt", "application/at+jwt"}
CLIENT_TYPES = {"web", "ssr", "app", "miniapp", "m2m"}
B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class AuthError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ProgrammingError(Exception):
    pass


def _b64d(s: str) -> bytes:
    if not B64URL.match(s):
        raise AuthError("AUTH_TOKEN_INVALID")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise AuthError("AUTH_TOKEN_INVALID")


def _json_obj(raw: bytes) -> dict:
    try:
        v = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise AuthError("AUTH_TOKEN_INVALID")
    if not isinstance(v, dict):
        raise AuthError("AUTH_TOKEN_INVALID")
    return v


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and v != ""


class Verifier:
    def __init__(self, *, issuer: str, client_id: str, clock_skew: int, jwks: dict,
                 refresh_jwks: Callable[[], dict] | None = None,
                 revocations: list[dict] | None = None, now: Callable[[], int]):
        self.issuer = issuer
        self.client_id = client_id
        self.skew = clock_skew
        self.keys = {k["kid"]: k for k in jwks["keys"]}
        self.refresh_jwks = refresh_jwks
        self.refreshed = False
        self.revocations = revocations or []
        self.now = now

    # ---------------------------------------------------------- keys
    def _find_key(self, kid: str) -> dict | None:
        if kid in self.keys:
            return self.keys[kid]
        if self.refresh_jwks and not self.refreshed:  # 未知 kid 至多刷新一次
            self.refreshed = True
            self.keys = {k["kid"]: k for k in self.refresh_jwks()["keys"]}
        return self.keys.get(kid)

    # ---------------------------------------------------------- verify
    def verify(self, token: str | None) -> dict:
        # 1
        if token is None or token == "":
            raise AuthError("AUTH_TOKEN_MISSING")
        # 2
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthError("AUTH_TOKEN_INVALID")
        h_b64, p_b64, s_b64 = parts
        header = _json_obj(_b64d(h_b64))
        # 3
        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower() not in ACCEPTED_TYP:
            raise AuthError("AUTH_TOKEN_INVALID")
        # 4
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:
            raise AuthError("AUTH_TOKEN_INVALID")
        # 5
        kid = header.get("kid")
        if not _is_nonempty_str(kid):
            raise AuthError("AUTH_TOKEN_INVALID")
        jwk = self._find_key(kid)
        if jwk is None:
            raise AuthError("AUTH_TOKEN_INVALID")
        kty, crv = ALLOWED_ALGS[alg]
        if jwk.get("kty") != kty or (crv and jwk.get("crv") != crv):
            raise AuthError("AUTH_TOKEN_INVALID")
        # 6
        sig = _b64d(s_b64)
        signing_input = f"{h_b64}.{p_b64}".encode()
        if kty == "RSA":
            algo, pub = RSAAlgorithm(RSAAlgorithm.SHA256), RSAAlgorithm.from_jwk(json.dumps(jwk))
        else:
            algo, pub = ECAlgorithm(ECAlgorithm.SHA256), ECAlgorithm.from_jwk(json.dumps(jwk))
        try:
            valid = algo.verify(signing_input, pub, sig)
        except Exception:
            valid = False
        if not valid:
            raise AuthError("AUTH_TOKEN_INVALID")
        # 7
        c = _json_obj(_b64d(p_b64))
        self._check_claims(c)
        # 8
        if c["iss"] != self.issuer:
            raise AuthError("AUTH_TOKEN_INVALID")
        now = self.now()
        # 9
        if now > c["exp"] + self.skew:
            raise AuthError("AUTH_TOKEN_EXPIRED")
        # 10
        if ("nbf" in c and now + self.skew < c["nbf"]) or now + self.skew < c["iat"]:
            raise AuthError("AUTH_TOKEN_INVALID")
        # 11
        aud = c["aud"]
        auds = [aud] if isinstance(aud, str) else aud
        if self.client_id not in auds:
            raise AuthError("AUTH_AUDIENCE_MISMATCH")
        # 12
        if self._revoked(c, auds):
            raise AuthError("AUTH_SESSION_REVOKED")
        return self._user(c)

    @staticmethod
    def _check_claims(c: dict) -> None:
        def req(cond: bool):
            if not cond:
                raise AuthError("AUTH_TOKEN_INVALID")

        req(isinstance(c.get("iss"), str))
        req(_is_nonempty_str(c.get("sub")))
        aud = c.get("aud")
        req(_is_nonempty_str(aud) or (isinstance(aud, list) and len(aud) > 0 and all(_is_nonempty_str(a) for a in aud)))
        req(_is_int(c.get("exp")))
        req(_is_int(c.get("iat")))
        req(_is_nonempty_str(c.get("jti")))
        req(_is_nonempty_str(c.get("azp")))
        req(c.get("client_type") in CLIENT_TYPES)
        req(_is_int(c.get("perm_ver")) and c["perm_ver"] >= 0)
        if c["client_type"] != "m2m":
            req(_is_nonempty_str(c.get("sid")))
            req(_is_nonempty_str(c.get("asid")))
        for k in ("name", "email", "dept_id", "dept_name", "scope"):
            req(k not in c or isinstance(c[k], str))
        for k in ("nbf", "auth_time"):
            req(k not in c or _is_int(c[k]))
        req("amr" not in c or (isinstance(c["amr"], list) and all(isinstance(x, str) for x in c["amr"])))

    def _revoked(self, c: dict, auds: list[str]) -> bool:
        for e in self.revocations:
            t = e["type"]
            if t == "session" and c.get("sid") is not None and e.get("sid") == c.get("sid"):
                return True
            if t == "app_session" and c.get("asid") is not None and e.get("asid") == c.get("asid"):
                return True
            if t == "user" and e.get("sub") == c["sub"] and c["iat"] < e["not_before"]:
                return True
            if t == "client" and (e.get("client_id") == c["azp"] or e.get("client_id") in auds) \
                    and c["iat"] < e["not_before"]:
                return True
        return False

    @staticmethod
    def _user(c: dict) -> dict:
        def opt(k):
            v = c.get(k)
            return v if isinstance(v, str) and v != "" else None

        machine = c["client_type"] == "m2m"
        scope = c.get("scope")
        return {
            "emp_no": None if machine else c["sub"],
            "subject": c["sub"],
            "is_machine": machine,
            "name": opt("name"),
            "email": opt("email"),
            "dept_id": opt("dept_id"),
            "dept_name": opt("dept_name"),
            "client_id": c["azp"],
            "client_type": c["client_type"],
            "sid": None if machine else c["sid"],
            "asid": None if machine else c["asid"],
            "scopes": scope.split() if scope else [],
            "perm_ver": c["perm_ver"],
            "amr": c.get("amr", []),
            "auth_time": c.get("auth_time"),
            "token_id": c["jti"],
            "expires_at": c["exp"],
        }


# ============================================================== authorization
SEG = r"[a-z0-9][a-z0-9_-]{0,63}"
GRANTED_RE = re.compile(rf"^(\*|{SEG})(:(\*|{SEG})){{2}}$")
REQUIRED_RE = re.compile(rf"^{SEG}(:{SEG}){{2}}$")
SCOPE_ORDER = ["self", "dept", "dept_and_sub", "all"]


def has_perm(granted: list[str], required: str) -> bool:
    if not REQUIRED_RE.match(required):
        raise ProgrammingError(f"invalid required permission: {required}")
    r = required.split(":")
    for g in granted:
        if not GRANTED_RE.match(g):
            continue  # 非法授予：忽略并告警
        if all(gs == "*" or gs == rs for gs, rs in zip(g.split(":"), r)):
            return True
    return False


def require(granted: list[str], mode: str, required: list[str]) -> bool:
    if not required:
        raise ProgrammingError("empty permission list")
    results = [has_perm(granted, r) for r in required]
    return all(results) if mode == "all" else any(results)


def effective_data_scope(role_scopes: list[str | None], dept_id: str | None) -> str | None:
    scopes = [s for s in role_scopes if s is not None]
    if not scopes:
        return None
    widest = max(scopes, key=SCOPE_ORDER.index)
    if widest in ("dept", "dept_and_sub") and dept_id is None:
        return "self"
    return widest
