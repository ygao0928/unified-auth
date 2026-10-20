#!/usr/bin/env python3
"""生成一致性测试向量。

用法：python3 conformance/tools/generate.py [--rotate-keys]

- 测试密钥保存在 conformance/keys/（仅供测试，绝不可用于任何环境）。
  默认复用已有密钥，保证重新生成时 JWKS 稳定；--rotate-keys 强制重建。
- 所有 token 基于固定时间 NOW 签发，SDK 测试时必须注入时钟 now = vectors 中的 "now"。
- 生成后请运行 run_reference.py 校验向量自洽。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ROOT = Path(__file__).resolve().parents[1]
KEYS = ROOT / "keys"
VECTORS = ROOT / "vectors"

SPEC_VERSION = "0.1.0"
NOW = int(datetime(2026, 10, 19, 2, 0, 0, tzinfo=timezone.utc).timestamp())
ISSUER = "https://auth.example.test"
CLIENT_ID = "meeting"
CLOCK_SKEW = 60
AT_TTL = 600

# kid -> (类型, 是否出现在初始 JWKS, 是否出现在刷新后 JWKS)
KEY_SPECS = {
    "rsa-1": ("RSA", True, True),
    "rsa-2": ("RSA", True, True),
    "ec-1": ("EC", True, True),
    "rsa-3": ("RSA", False, True),   # 模拟轮换：刷新 JWKS 后才出现
    "attacker": ("RSA", False, False),  # 攻击者密钥，永不发布
}


# ---------------------------------------------------------------- keys
def load_or_create_keys(rotate: bool) -> dict:
    KEYS.mkdir(parents=True, exist_ok=True)
    keys = {}
    for kid, (kty, _, _) in KEY_SPECS.items():
        path = KEYS / f"{kid}.private.pem"
        if path.exists() and not rotate:
            keys[kid] = serialization.load_pem_private_key(path.read_bytes(), password=None)
            continue
        if kty == "RSA":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            key = ec.generate_private_key(ec.SECP256R1())
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        keys[kid] = key
    return keys


def public_jwk(kid: str, key) -> dict:
    if isinstance(key, rsa.RSAPrivateKey):
        jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    else:
        jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": kid, "use": "sig", "alg": "ES256"})
    return {k: jwk[k] for k in sorted(jwk)}


def write_jwks(keys: dict) -> None:
    initial = [public_jwk(k, keys[k]) for k, (_, a, _) in KEY_SPECS.items() if a]
    rotated = [public_jwk(k, keys[k]) for k, (_, _, b) in KEY_SPECS.items() if b]
    dump(KEYS / "jwks.json", {"keys": initial})
    dump(KEYS / "jwks-rotated.json", {"keys": rotated})


# ---------------------------------------------------------------- signing
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign(claims: dict, keys: dict, kid: str = "rsa-1", *, alg: str | None = None,
         typ: str | None = "at+jwt", header_kid: str | None = "__same__") -> str:
    key = keys[kid]
    alg = alg or ("RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256")
    headers = {}
    if typ is not None:
        headers["typ"] = typ
    hk = kid if header_kid == "__same__" else header_kid
    if hk is not None:
        headers["kid"] = hk
    token = jwt.encode(claims, key, algorithm=alg, headers=headers)
    # PyJWT 在 typ=None 时仍可能写入默认 typ，这里重建头部以精确控制
    if typ is None or hk is None:
        header = {"alg": alg}
        if hk is not None:
            header["kid"] = hk
        if typ is not None:
            header["typ"] = typ
        return raw_sign(header, claims, key, alg)
    return token


def raw_sign(header: dict, claims: dict, key, alg: str) -> str:
    signing_input = f"{b64u(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64u(json.dumps(claims, separators=(',', ':'), ensure_ascii=False).encode())}"
    algo = jwt.get_algorithm_by_name(alg)
    sig = algo.sign(signing_input.encode(), key)
    return f"{signing_input}.{b64u(sig)}"


def unsigned(claims: dict, kid: str = "rsa-1") -> str:
    header = {"alg": "none", "typ": "at+jwt", "kid": kid}
    return f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}."


def hs256_with_public_key(claims: dict, keys: dict, kid: str = "rsa-1") -> str:
    """算法混淆攻击：用 RSA 公钥 PEM 作为 HMAC 密钥签名。"""
    header = {"alg": "HS256", "typ": "at+jwt", "kid": kid}
    pub_pem = keys[kid].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}"
    sig = hmac.new(pub_pem, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64u(sig)}"


# ---------------------------------------------------------------- claims
def base_claims(**overrides) -> dict:
    c = {
        "iss": ISSUER,
        "sub": "E10023",
        "aud": CLIENT_ID,
        "exp": NOW + AT_TTL - 60,
        "iat": NOW - 60,
        "jti": "jti-0001",
        "azp": CLIENT_ID,
        "client_type": "web",
        "perm_ver": 7,
        "sid": "bj1.sess-0001",
        "asid": "as.app-0001",
    }
    for k, v in overrides.items():
        if v is DROP:
            c.pop(k, None)
        else:
            c[k] = v
    return c


DROP = object()

FULL_OPTIONAL = {
    "name": "张三",
    "email": "zhangsan@corp.example",
    "dept_id": "D1002",
    "dept_name": "研发一部",
    "scope": "openid profile meeting.read",
    "amr": ["pwd", "otp"],
    "auth_time": NOW - 120,
}


def expected_user(c: dict) -> dict:
    """按 spec/token-validation.md#输出-User 构造期望 User。"""
    def opt(name):
        v = c.get(name)
        return v if isinstance(v, str) and v != "" else None

    machine = c["client_type"] == "m2m"
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
        "scopes": c["scope"].split() if isinstance(c.get("scope"), str) and c["scope"] else [],
        "perm_ver": c["perm_ver"],
        "amr": c.get("amr", []),
        "auth_time": c.get("auth_time"),
        "token_id": c["jti"],
        "expires_at": c["exp"],
    }


def ok(cid: str, desc: str, token: str, claims: dict, **extra) -> dict:
    return {"id": cid, "description": desc, "token": token, **extra,
            "expect": {"valid": True, "error": None, "user": expected_user(claims)}}


def bad(cid: str, desc: str, token, error: str, **extra) -> dict:
    return {"id": cid, "description": desc, "token": token, **extra,
            "expect": {"valid": False, "error": error, "user": None}}


def rev(id_, type_, **kw) -> dict:
    e = {"id": id_, "event": "auth.revoked", "type": type_, "ts": NOW - 30, "reason": kw.pop("reason", "admin_kick")}
    e.update(kw)
    return e


# ---------------------------------------------------------------- cases
def build_token_cases(keys: dict) -> list[dict]:
    cases = []
    full = base_claims(**FULL_OPTIONAL)
    minimal = base_claims()

    # ---- 正常路径
    cases.append(ok("valid_full", "全部可选 claims 齐全", sign(full, keys), full))
    cases.append(ok("valid_minimal", "只有必填 claims，可选字段全部缺失 → User 对应字段为 null/[]", sign(minimal, keys), minimal))
    c = base_claims(name="", dept_id="")
    cases.append(ok("valid_empty_optional_strings", "可选字符串为空串视同不存在", sign(c, keys), c))
    c = base_claims(aud=["gateway", CLIENT_ID])
    cases.append(ok("valid_aud_array", "aud 为数组且包含本应用", sign(c, keys), c))
    c = base_claims(x_unknown="ignored", ext={"a": 1})
    cases.append(ok("valid_unknown_claims", "未知 claims 必须忽略", sign(c, keys), c))
    cases.append(ok("valid_second_key", "使用 JWKS 中第二把 RSA 密钥签名", sign(minimal, keys, "rsa-2"), minimal))
    cases.append(ok("valid_es256", "ES256 签名", sign(minimal, keys, "ec-1"), minimal))
    cases.append(ok("valid_kid_after_refresh", "kid 不在初始 JWKS，刷新一次后出现（密钥轮换）",
                    sign(minimal, keys, "rsa-3"), minimal))
    cases.append(ok("valid_typ_application_at_jwt", "typ=application/at+jwt 等价于 at+jwt",
                    sign(minimal, keys, typ="application/at+jwt"), minimal))
    cases.append(ok("valid_typ_case_insensitive", "typ 比较不区分大小写",
                    sign(minimal, keys, typ="AT+JWT"), minimal))
    c = base_claims(client_type="m2m", sub="client:report-job", azp="report-job", sid=DROP, asid=DROP,
                    scope="meeting.read")
    cases.append(ok("valid_m2m", "m2m token：无 sid/asid，emp_no 为 null", sign(c, keys), c))
    c = base_claims(exp=NOW - 30)
    cases.append(ok("valid_expired_within_skew", "过期 30 秒，仍在 60 秒容差内", sign(c, keys), c))
    c = base_claims(nbf=NOW + 30, iat=NOW + 30)
    cases.append(ok("valid_nbf_within_skew", "nbf/iat 在未来 30 秒，仍在容差内", sign(c, keys), c))
    c = base_claims(exp=NOW - 60)
    cases.append(ok("valid_expired_exact_skew_boundary", "now == exp + skew 时仍有效（判定条件为 >）", sign(c, keys), c))

    # ---- 步骤 1：缺失
    cases.append(bad("missing_token_null", "token 不存在", None, "AUTH_TOKEN_MISSING"))
    cases.append(bad("missing_token_empty", "token 为空字符串", "", "AUTH_TOKEN_MISSING"))

    # ---- 步骤 2：格式
    cases.append(bad("malformed_two_segments", "只有两段", "abc.def", "AUTH_TOKEN_INVALID"))
    cases.append(bad("malformed_garbage", "非 base64url 内容", "!!!.@@@.###", "AUTH_TOKEN_INVALID"))
    cases.append(bad("malformed_header_not_json", "头部不是 JSON",
                     f"{b64u(b'not-json')}.{b64u(b'{}')}.{b64u(b'sig')}", "AUTH_TOKEN_INVALID"))
    cases.append(bad("malformed_header_json_array", "头部是 JSON 数组而非对象",
                     f"{b64u(b'[1]')}.{b64u(b'{}')}.{b64u(b'sig')}", "AUTH_TOKEN_INVALID"))

    # ---- 步骤 3：typ
    cases.append(bad("typ_jwt_id_token_misuse", "typ=JWT（ID Token 冒充 Access Token）",
                     sign(minimal, keys, typ="JWT"), "AUTH_TOKEN_INVALID"))
    cases.append(bad("typ_missing", "缺少 typ 头", sign(minimal, keys, typ=None), "AUTH_TOKEN_INVALID"))

    # ---- 步骤 4：alg
    cases.append(bad("alg_none", "alg=none 未签名 token", unsigned(minimal), "AUTH_TOKEN_INVALID"))
    cases.append(bad("alg_hs256_confusion", "HS256 + RSA 公钥作为 HMAC 密钥（算法混淆攻击）",
                     hs256_with_public_key(minimal, keys), "AUTH_TOKEN_INVALID"))
    cases.append(bad("alg_rs512_not_allowed", "RS512 不在白名单",
                     sign(minimal, keys, alg="RS512"), "AUTH_TOKEN_INVALID"))

    # ---- 步骤 5：kid
    cases.append(bad("kid_missing", "缺少 kid 头", sign(minimal, keys, header_kid=None), "AUTH_TOKEN_INVALID"))
    cases.append(bad("kid_unknown_after_refresh", "kid 在刷新后仍不存在",
                     sign(minimal, keys, "attacker", header_kid="rsa-9"), "AUTH_TOKEN_INVALID"))
    cases.append(bad("kid_alg_kty_mismatch", "alg=ES256 但 kid 指向 RSA 密钥",
                     raw_sign({"alg": "ES256", "typ": "at+jwt", "kid": "rsa-1"}, minimal, keys["ec-1"], "ES256"),
                     "AUTH_TOKEN_INVALID"))

    # ---- 步骤 6：签名
    cases.append(bad("signature_wrong_key", "攻击者密钥签名但声明 kid=rsa-1",
                     sign(minimal, keys, "attacker", header_kid="rsa-1"), "AUTH_TOKEN_INVALID"))
    t = sign(minimal, keys)
    h, p, s = t.split(".")
    tampered = base_claims(sub="E99999")
    cases.append(bad("signature_payload_tampered", "篡改 payload（sub）后签名不匹配",
                     f"{h}.{b64u(json.dumps(tampered).encode())}.{s}", "AUTH_TOKEN_INVALID"))

    # ---- 步骤 7：必填 claims
    for claim in ["sub", "jti", "azp", "client_type", "perm_ver", "sid", "asid", "exp", "iat", "aud", "iss"]:
        c = base_claims(**{claim: DROP})
        cases.append(bad(f"claim_missing_{claim}", f"缺少必填 claim {claim}", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(sub="")
    cases.append(bad("claim_empty_sub", "sub 为空字符串", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(exp=str(NOW + 600))
    cases.append(bad("claim_exp_wrong_type", "exp 为字符串", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(perm_ver=-1)
    cases.append(bad("claim_perm_ver_negative", "perm_ver 为负数", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(client_type="desktop")
    cases.append(bad("claim_client_type_unknown", "client_type 不在枚举内", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(name=123)
    cases.append(bad("claim_optional_wrong_type", "可选 claim name 类型错误", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(aud=[])
    cases.append(bad("claim_aud_empty_array", "aud 为空数组", sign(c, keys), "AUTH_TOKEN_INVALID"))

    # ---- 步骤 8：iss
    c = base_claims(iss=ISSUER + "/")
    cases.append(bad("iss_trailing_slash", "iss 多一个尾部斜杠（不做归一化）", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(iss="https://evil.example.test")
    cases.append(bad("iss_other", "iss 为其他签发方", sign(c, keys), "AUTH_TOKEN_INVALID"))

    # ---- 步骤 9：过期
    c = base_claims(exp=NOW - 61)
    cases.append(bad("expired_beyond_skew", "过期 61 秒，超出容差", sign(c, keys), "AUTH_TOKEN_EXPIRED"))
    c = base_claims(exp=NOW - 3600, aud="other-app")
    cases.append(bad("expired_and_wrong_aud", "同时过期且 aud 错误 → 按步骤顺序返回 EXPIRED", sign(c, keys),
                     "AUTH_TOKEN_EXPIRED"))

    # ---- 步骤 10：nbf / iat
    c = base_claims(nbf=NOW + 120)
    cases.append(bad("nbf_future", "nbf 在未来 120 秒", sign(c, keys), "AUTH_TOKEN_INVALID"))
    c = base_claims(iat=NOW + 120)
    cases.append(bad("iat_future", "iat 在未来 120 秒", sign(c, keys), "AUTH_TOKEN_INVALID"))

    # ---- 步骤 11：aud
    c = base_claims(aud="other-app")
    cases.append(bad("aud_mismatch", "aud 为其他应用", sign(c, keys), "AUTH_AUDIENCE_MISMATCH"))
    c = base_claims(aud=["gateway", "other-app"])
    cases.append(bad("aud_array_mismatch", "aud 数组不包含本应用", sign(c, keys), "AUTH_AUDIENCE_MISMATCH"))
    c = base_claims(aud="Meeting")
    cases.append(bad("aud_case_sensitive", "aud 区分大小写", sign(c, keys), "AUTH_AUDIENCE_MISMATCH"))

    # ---- 步骤 12：吊销
    t = sign(minimal, keys)
    cases.append(bad("revoked_session", "全局会话被吊销", t, "AUTH_SESSION_REVOKED",
                     revocations=[rev("rv-1", "session", sid="bj1.sess-0001")]))
    cases.append(bad("revoked_app_session", "应用会话被吊销", t, "AUTH_SESSION_REVOKED",
                     revocations=[rev("rv-2", "app_session", asid="as.app-0001")]))
    cases.append(bad("revoked_user_before_iat", "用户被吊销，token 签发早于 not_before", t, "AUTH_SESSION_REVOKED",
                     revocations=[rev("rv-3", "user", sub="E10023", not_before=NOW - 30, reason="user_disabled")]))
    cases.append(ok("revoked_user_token_issued_after", "用户被吊销后重新登录签发的 token 不受影响",
                    t, minimal, revocations=[rev("rv-4", "user", sub="E10023", not_before=NOW - 120)]))
    cases.append(bad("revoked_client_by_azp", "客户端被禁用（匹配 azp）", t, "AUTH_SESSION_REVOKED",
                     revocations=[rev("rv-5", "client", client_id=CLIENT_ID, not_before=NOW - 30,
                                      reason="client_disabled")]))
    c = base_claims(aud=["meeting", "gateway"])
    cases.append(bad("revoked_client_by_aud", "客户端被禁用（匹配 aud 数组中的另一受众，azp 不匹配）", sign(c, keys), "AUTH_SESSION_REVOKED",
                     revocations=[rev("rv-6", "client", client_id="gateway", not_before=NOW - 30,
                                      reason="client_disabled")]))
    cases.append(ok("revoked_other_session_no_effect", "其他会话被吊销不影响本 token", t, minimal,
                    revocations=[rev("rv-7", "session", sid="bj1.sess-9999"),
                                 rev("rv-8", "app_session", asid="as.app-9999"),
                                 rev("rv-9", "user", sub="E99999", not_before=NOW)]))
    m2m = base_claims(client_type="m2m", sub="client:report-job", azp="report-job", sid=DROP, asid=DROP)
    cases.append(ok("revoked_session_m2m_unaffected", "m2m token 无 sid，session 吊销不影响",
                    sign(m2m, keys), m2m, revocations=[rev("rv-10", "session", sid="bj1.sess-0001")]))

    return cases


# ---------------------------------------------------------------- authz cases
def build_authz_cases() -> dict:
    granted_basic = ["meeting:user:list", "meeting:record:*", "*:audit:view"]
    has_perm = [
        ("exact_match", granted_basic, "meeting:user:list", True),
        ("no_match", granted_basic, "meeting:user:delete", False),
        ("wildcard_action", granted_basic, "meeting:record:export", True),
        ("wildcard_app", granted_basic, "crm:audit:view", True),
        ("wildcard_app_other_resource", granted_basic, "crm:audit:export", False),
        ("superadmin", ["*:*:*"], "anything:at:all", True),
        ("empty_granted", [], "meeting:user:list", False),
        ("case_sensitive", ["meeting:user:list"], "meeting:User:list", "programming_error"),
        ("required_with_wildcard", granted_basic, "meeting:user:*", "programming_error"),
        ("required_two_segments", granted_basic, "meeting:user", "programming_error"),
        ("invalid_granted_two_segments_ignored", ["meeting:*"], "meeting:user:list", False),
        ("invalid_granted_uppercase_ignored", ["Meeting:user:list"], "meeting:user:list", False),
        ("invalid_granted_mixed", ["meeting:*", "meeting:user:list"], "meeting:user:list", True),
        ("wildcard_no_prefix_match", ["meeting:rec*:export"], "meeting:record:export", False),
    ]
    combos = [
        ("require_all_ok", granted_basic, "all", ["meeting:user:list", "meeting:record:export"], True),
        ("require_all_fail", granted_basic, "all", ["meeting:user:list", "meeting:user:delete"], False),
        ("require_any_ok", granted_basic, "any", ["meeting:user:delete", "meeting:record:export"], True),
        ("require_any_fail", granted_basic, "any", ["meeting:user:delete", "crm:user:list"], False),
        ("require_all_empty", granted_basic, "all", [], "programming_error"),
        ("require_any_empty", granted_basic, "any", [], "programming_error"),
    ]
    data_scope = [
        ("single_self", ["self"], "D1", "self"),
        ("widest_wins", ["self", "dept_and_sub", "dept"], "D1", "dept_and_sub"),
        ("all_wins", ["dept", "all"], "D1", "all"),
        ("null_ignored", [None, "dept"], "D1", "dept"),
        ("all_null", [None, None], "D1", None),
        ("no_roles", [], "D1", None),
        ("dept_degrade_no_dept", ["dept"], None, "self"),
        ("dept_and_sub_degrade_no_dept", ["dept_and_sub", "self"], None, "self"),
        ("all_no_degrade", ["all"], None, "all"),
        ("self_no_dept", ["self"], None, "self"),
    ]
    return {
        "spec_version": SPEC_VERSION,
        "has_perm": [{"id": i, "granted": g, "required": r, "expect": e} for i, g, r, e in has_perm],
        "combinations": [{"id": i, "granted": g, "mode": m, "required": r, "expect": e} for i, g, m, r, e in combos],
        "data_scope": [{"id": i, "role_scopes": s, "dept_id": d, "expect": e} for i, s, d, e in data_scope],
    }


def dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rotate-keys", action="store_true", help="重建全部测试密钥")
    args = ap.parse_args()

    keys = load_or_create_keys(args.rotate_keys)
    write_jwks(keys)
    cases = build_token_cases(keys)
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "case id 重复"
    dump(VECTORS / "token-cases.json", {
        "spec_version": SPEC_VERSION,
        "now": NOW,
        "config": {"issuer": ISSUER, "client_id": CLIENT_ID, "clock_skew": CLOCK_SKEW},
        "jwks": {"initial": "../keys/jwks.json", "after_refresh": "../keys/jwks-rotated.json"},
        "cases": cases,
    })
    dump(VECTORS / "authz-cases.json", build_authz_cases())
    print(f"generated {len(cases)} token cases -> {VECTORS / 'token-cases.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
