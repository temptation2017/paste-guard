import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import paste_guard as pg  # noqa: E402

# 测试用的假凭据在运行时拼出来，避免仓库里出现长得像真凭据的字符串。
FAKE_GH = "gh" + "p_" + "A1b2C3d4" * 5
FAKE_OPENAI = "sk-" + "proj-" + "Zz9" * 10
FAKE_ANTHROPIC = "sk-" + "ant-" + "api03-" + "Qq7" * 10
FAKE_PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASC\n-----END " + "PRIVATE KEY-----"


def fake_id(prefix17):
    total = sum(int(c) * w for c, w in zip(prefix17, pg.ID_WEIGHTS))
    return prefix17 + pg.ID_CHECK[total % 11]


def names(text, **kw):
    return [f.rule.name for f in pg.scan_text(text, **kw)]


class DetectTests(unittest.TestCase):
    def test_tokens(self):
        self.assertEqual(names("token=" + FAKE_GH), ["GITHUB_TOKEN"])
        self.assertEqual(names("key " + FAKE_OPENAI), ["OPENAI_KEY"])
        self.assertEqual(names("key " + FAKE_ANTHROPIC), ["ANTHROPIC_KEY"])
        self.assertEqual(names("x " + FAKE_PEM + " y"), ["PRIVATE_KEY"])
        self.assertEqual(names("AKIAIOSFODNN7EXAMPLE"), ["AWS_ACCESS_KEY"])

    def test_cn_id_checksum(self):
        good = fake_id("11010119900307123")
        bad = good[:-1] + ("0" if good[-1] != "0" else "1")
        self.assertEqual(names("证件 " + good), ["CN_ID"])
        self.assertNotIn("CN_ID", names("证件 " + bad))

    def test_mobile_boundaries(self):
        self.assertEqual(names("电话13800138000。"), ["CN_MOBILE"])
        self.assertEqual(names("电话 +86 138-0013-8000"), ["CN_MOBILE"])
        self.assertEqual(names("订单号 9913800138000123"), [])
        self.assertEqual(names("12800138000"), [])

    def test_bank_card_luhn(self):
        self.assertEqual(names("卡号 4111 1111 1111 1111"), ["BANK_CARD"])
        self.assertEqual(names("卡号 4111 1111 1111 1112"), [])
        self.assertEqual(names("0000000000000000"), [])

    def test_plate_and_email(self):
        self.assertEqual(names("车牌 沪B·D12345 已登记"), ["CN_PLATE"])
        self.assertEqual(names("mail: someone@example.org"), ["EMAIL"])

    def test_password_and_url(self):
        self.assertEqual(names("password = 'abc12345'"), ["PASSWORD_ASSIGN"])
        self.assertEqual(names("密码：Abc12345"), ["PASSWORD_ASSIGN"])
        f = pg.scan_text("redis://user:pa55word@host:6379/0")
        self.assertEqual(f[0].value, "pa55word")

    def test_no_overlap_jwt_vs_password(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcDEF123456ghiJKL"
        found = pg.scan_text("access_token=" + jwt)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].rule.name, "JWT")

    def test_allowlist_and_rule_filter(self):
        text = "a@example.com b@test.dev 13800138000"
        self.assertEqual(names(text, allowlist=["*@example.com"]), ["EMAIL", "CN_MOBILE"])
        rules = pg.pick_rules("cn_mobile", None)
        self.assertEqual(names(text, rules=rules), ["CN_MOBILE"])
        rules = pg.pick_rules(None, "EMAIL")
        self.assertEqual(names(text, rules=rules), ["CN_MOBILE"])
        with self.assertRaises(SystemExit):
            pg.pick_rules("NOPE", None)


class RedactTests(unittest.TestCase):
    def test_same_value_same_placeholder(self):
        text = "A 138-0013-8000, B 13900139000, A again 13800138000"
        out = pg.redact_text(text, pg.scan_text(text))
        self.assertEqual(out, "A [CN_MOBILE_1], B [CN_MOBILE_2], A again [CN_MOBILE_1]")

    def test_redact_is_idempotent(self):
        once = pg.redact_text(pg.DEMO, pg.scan_text(pg.DEMO))
        self.assertEqual(pg.scan_text(once), [])

    def test_clean_text_unchanged(self):
        text = "今天天气不错，版本号 1.2.3，端口 8080。"
        self.assertEqual(pg.redact_text(text, pg.scan_text(text)), text)


class CliTests(unittest.TestCase):
    def run_cli(self, argv, stdin_text=None):
        out, err = io.StringIO(), io.StringIO()
        old_stdin = sys.stdin
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = pg.main(argv)
        finally:
            sys.stdin = old_stdin
        return code, out.getvalue(), err.getvalue()

    def test_scan_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            dirty = os.path.join(d, "a.txt")
            clean = os.path.join(d, "b.txt")
            with open(dirty, "w", encoding="utf-8") as f:
                f.write("line1\n联系 13800138000\n")
            with open(clean, "w", encoding="utf-8") as f:
                f.write("nothing here\n")
            code, out, _ = self.run_cli(["scan", "--format", "json", "--allowlist", "", d])
            self.assertEqual(code, 1)
            data = json.loads(out)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["line"], 2)
            self.assertNotIn("13800138000", out)
            code, _, _ = self.run_cli(["scan", "--allowlist", "", clean])
            self.assertEqual(code, 0)

    def test_redact_stdin(self):
        code, out, _ = self.run_cli(["redact", "--allowlist", ""], "key " + FAKE_GH + "\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, "key [GITHUB_TOKEN_1]\n")

    def test_allowlist_file(self):
        with tempfile.TemporaryDirectory() as d:
            allow = os.path.join(d, ".pasteguardignore")
            with open(allow, "w", encoding="utf-8") as f:
                f.write("# 公开客服邮箱\nsupport@example.com\n")
            code, _, _ = self.run_cli(["scan", "--allowlist", allow], "support@example.com")
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
