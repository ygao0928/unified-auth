#!/usr/bin/env python3
"""用参考实现跑全部一致性向量，并校验 spec 自身的一致性。

用法：python3 conformance/tools/run_reference.py
退出码非 0 表示向量与规范不一致，CI 中应作为门禁。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference import AuthError, ProgrammingError, Verifier, effective_data_scope, has_perm, require  # noqa: E402

CONF = Path(__file__).resolve().parents[1]
SPEC = CONF.parent / "spec"
failures: list[str] = []


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def schema(name: str) -> Draft202012Validator:
    s = load(SPEC / "schemas" / name)
    Draft202012Validator.check_schema(s)
    return Draft202012Validator(s)


def check(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)


def b64_payload(token: str) -> dict:
    import base64
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def run_token_cases() -> int:
    data = load(CONF / "vectors" / "token-cases.json")
    cfg = data["config"]
    jwks_initial = load((CONF / "vectors" / data["jwks"]["initial"]).resolve())
    jwks_after = load((CONF / "vectors" / data["jwks"]["after_refresh"]).resolve())
    claims_v, user_v, rev_v = schema("access-token-claims.schema.json"), schema("user.schema.json"), \
        schema("revocation-event.schema.json")
    codes = {c["code"] for c in yaml.safe_load((SPEC / "error-codes.yaml").read_text(encoding="utf-8"))["codes"]}

    for case in data["cases"]:
        cid = case["id"]
        for e in case.get("revocations", []):
            errs = [x.message for x in rev_v.iter_errors(e)]
            check(not errs, f"[{cid}] revocation event invalid: {errs}")
        v = Verifier(issuer=cfg["issuer"], client_id=cfg["client_id"], clock_skew=cfg["clock_skew"],
                     jwks=jwks_initial, refresh_jwks=lambda: jwks_after,
                     revocations=case.get("revocations"), now=lambda: data["now"])
        exp = case["expect"]
        try:
            user, err = v.verify(case["token"]), None
        except AuthError as e:
            user, err = None, e.code
        check(err == exp["error"], f"[{cid}] error: got {err}, want {exp['error']}")
        check(user == exp["user"], f"[{cid}] user mismatch:\n  got  {user}\n  want {exp['user']}")
        if exp["error"]:
            check(exp["error"] in codes, f"[{cid}] error code {exp['error']} not in error-codes.yaml")
        if exp["valid"]:
            errs = [x.message for x in claims_v.iter_errors(b64_payload(case["token"]))]
            check(not errs, f"[{cid}] valid token claims violate schema: {errs}")
            errs = [x.message for x in user_v.iter_errors(exp["user"])]
            check(not errs, f"[{cid}] expected user violates schema: {errs}")
    return len(data["cases"])


def run_authz_cases() -> int:
    data = load(CONF / "vectors" / "authz-cases.json")
    n = 0
    for c in data["has_perm"]:
        n += 1
        try:
            got = has_perm(c["granted"], c["required"])
        except ProgrammingError:
            got = "programming_error"
        check(got == c["expect"], f"[has_perm/{c['id']}] got {got}, want {c['expect']}")
    for c in data["combinations"]:
        n += 1
        try:
            got = require(c["granted"], c["mode"], c["required"])
        except ProgrammingError:
            got = "programming_error"
        check(got == c["expect"], f"[combinations/{c['id']}] got {got}, want {c['expect']}")
    for c in data["data_scope"]:
        n += 1
        got = effective_data_scope(c["role_scopes"], c["dept_id"])
        check(got == c["expect"], f"[data_scope/{c['id']}] got {got}, want {c['expect']}")
    return n


def check_schema_examples() -> int:
    n = 0
    for p in sorted((SPEC / "schemas").glob("*.json")):
        s = load(p)
        Draft202012Validator.check_schema(s)
        v = Draft202012Validator(s)
        for i, ex in enumerate(s.get("examples", [])):
            n += 1
            errs = [x.message for x in v.iter_errors(ex)]
            check(not errs, f"[{p.name} example {i}] {errs}")
    return n


def check_openapi() -> str:
    try:
        from openapi_spec_validator import validate
        from openapi_spec_validator.readers import read_from_filename
    except ImportError:
        return "skipped (pip install openapi-spec-validator)"
    path = SPEC / "openapi" / "auth-center.yaml"
    spec_dict, base_uri = read_from_filename(str(path))
    try:
        validate(spec_dict, base_uri=base_uri)
        return "ok"
    except Exception as e:  # noqa: BLE001
        failures.append(f"[openapi] {e}")
        return "FAILED"


def main() -> int:
    t = run_token_cases()
    a = run_authz_cases()
    s = check_schema_examples()
    o = check_openapi()
    print(f"token cases: {t}  authz cases: {a}  schema examples: {s}  openapi: {o}")
    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for f in failures:
            print(" -", f)
        return 1
    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
