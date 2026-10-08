#!/usr/bin/env python3
"""paste-guard: 把文本贴给 AI 之前，先扫一遍密钥和个人信息，并按需脱敏。

只用 Python 标准库，单文件即可运行。
"""

import argparse
import fnmatch
import json
import os
import re
import sys

__version__ = "0.1.0"

ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
ID_CHECK = "10X98765432"

PLATE_PROVINCES = "京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼"


def cn_id_valid(value):
    v = value.upper()
    if len(v) != 18 or not v[:17].isdigit():
        return False
    month, day = int(v[10:12]), int(v[12:14])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    total = sum(int(c) * w for c, w in zip(v[:17], ID_WEIGHTS))
    return ID_CHECK[total % 11] == v[17]


def luhn_valid(value):
    digits = [int(c) for c in value if c.isdigit()]
    if not 16 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


PLACEHOLDER = re.compile(r"\[[A-Z_]+_\d+\]")


def not_placeholder(value):
    # 已经脱敏过的文本再跑一遍，不应该把占位符当成密码。
    return not PLACEHOLDER.fullmatch(value)


class Rule:
    def __init__(self, name, label, pattern, group=0, check=None, flags=0):
        self.name = name
        self.label = label
        self.regex = re.compile(pattern, flags)
        self.group = group
        self.check = check


# 顺序有意义：越具体的规则越靠前，重叠时先到先得。
RULES = [
    Rule("PRIVATE_KEY", "私钥块",
         r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----"),
    Rule("AWS_ACCESS_KEY", "AWS Access Key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    Rule("GITHUB_TOKEN", "GitHub Token",
         r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    Rule("ANTHROPIC_KEY", "Anthropic Key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    Rule("OPENAI_KEY", "OpenAI 风格 Key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    Rule("SLACK_TOKEN", "Slack Token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    Rule("GOOGLE_API_KEY", "Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}"),
    Rule("JWT", "JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    Rule("URL_CREDENTIAL", "URL 内嵌账号密码",
         r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s@/`]+)@", group=1, check=not_placeholder),
    Rule("PASSWORD_ASSIGN", "密码/密钥赋值",
         r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|密码)\s*[:=：]\s*[\"'`]?([^\s\"'`,;]{4,})",
         group=1, check=not_placeholder),
    Rule("CN_ID", "身份证号", r"(?<!\d)\d{17}[\dXx](?![\dA-Za-z])", check=cn_id_valid),
    Rule("BANK_CARD", "银行卡号", r"(?<!\d)(?:\d[ \-]?){15,18}\d(?!\d)", check=luhn_valid),
    Rule("CN_MOBILE", "手机号", r"(?<!\d)(?:\+?86[ \-]?)?1[3-9]\d[ \-]?\d{4}[ \-]?\d{4}(?!\d)"),
    Rule("EMAIL", "邮箱", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    Rule("CN_PLATE", "车牌号",
         r"(?<![A-Za-z0-9])[" + PLATE_PROVINCES + r"][A-HJ-NP-Z]·?(?:[A-HJ-NP-Z0-9]{5}|[DF][A-HJ-NP-Z0-9]{5}|[A-HJ-NP-Z0-9]{5}[DF])(?![A-Za-z0-9])"),
]

RULE_NAMES = [r.name for r in RULES]


class Finding:
    __slots__ = ("rule", "start", "end", "value", "line", "col")

    def __init__(self, rule, start, end, value, line, col):
        self.rule = rule
        self.start = start
        self.end = end
        self.value = value
        self.line = line
        self.col = col


def mask(value):
    v = value.replace("\n", " ")
    if len(v) <= 6:
        return "*" * len(v)
    keep = 2 if len(v) < 12 else 4
    return v[:keep] + "*" * min(len(v) - keep * 2, 12) + v[-keep:]


def load_allowlist(path):
    items = []
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for raw in f:
                s = raw.strip()
                if s and not s.startswith("#"):
                    items.append(s)
    return items


def allowed(value, allowlist):
    for item in allowlist:
        if value == item or fnmatch.fnmatchcase(value, item):
            return True
    return False


def scan_text(text, rules=None, allowlist=()):
    """返回按出现位置排序、互不重叠的命中列表。"""
    active = rules or RULES
    taken = []
    found = []
    for rule in active:
        for m in rule.regex.finditer(text):
            start, end = m.span(rule.group)
            value = m.group(rule.group)
            if rule.check and not rule.check(value):
                continue
            if allowed(value, allowlist):
                continue
            if any(start < e and s < end for s, e in taken):
                continue
            taken.append((start, end))
            line = text.count("\n", 0, start) + 1
            col = start - (text.rfind("\n", 0, start) + 1) + 1
            found.append(Finding(rule, start, end, value, line, col))
    found.sort(key=lambda f: f.start)
    return found


NUMERIC_RULES = {"CN_MOBILE", "BANK_CARD", "CN_ID"}


def normalize(rule_name, value):
    if rule_name in NUMERIC_RULES:
        v = re.sub(r"[^0-9Xx]", "", value).upper()
        if rule_name == "CN_MOBILE" and len(v) == 13 and v.startswith("86"):
            v = v[2:]
        return v
    if rule_name == "EMAIL":
        return value.lower()
    if rule_name == "CN_PLATE":
        return value.replace("·", "")
    return value


def redact_text(text, findings):
    """同一个值在全文里用同一个占位符，写法不同（如带不带横杠）也算同一个。"""
    numbering = {}
    counters = {}
    out = []
    pos = 0
    for f in findings:
        key = (f.rule.name, normalize(f.rule.name, f.value))
        if key not in numbering:
            counters[f.rule.name] = counters.get(f.rule.name, 0) + 1
            numbering[key] = counters[f.rule.name]
        out.append(text[pos:f.start])
        out.append("[%s_%d]" % (f.rule.name, numbering[key]))
        pos = f.end
    out.append(text[pos:])
    return "".join(out)


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".idea"}
MAX_BYTES = 2 * 1024 * 1024


def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    yield os.path.join(root, name)
        else:
            yield p


def read_text(path):
    if os.path.getsize(path) > MAX_BYTES:
        return None
    with open(path, "rb") as f:
        data = f.read()
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def pick_rules(only, skip):
    rules = RULES
    if only:
        wanted = {x.strip().upper() for x in only.split(",") if x.strip()}
        bad = wanted - set(RULE_NAMES)
        if bad:
            raise SystemExit("未知规则: %s" % ", ".join(sorted(bad)))
        rules = [r for r in rules if r.name in wanted]
    if skip:
        drop = {x.strip().upper() for x in skip.split(",") if x.strip()}
        rules = [r for r in rules if r.name not in drop]
    return rules


DEMO = """\
# 这是一段虚构的示例，所有数据都不真实
DATABASE_URL=postgres://admin:hunter2pass@db.example.com:5432/app
aws_key = AKIAIOSFODNN7EXAMPLE
password: S3cretDemo!
联系人：张三，手机 138-0013-8000，邮箱 zhangsan@example.com
身份证 11010519491231002X，车牌 京A·12345
备注：手机 13800138000 与上面是同一个号码
"""


def cmd_scan(args, rules, allowlist):
    report = []
    sources = list(iter_files(args.paths)) if args.paths else ["-"]
    for src in sources:
        if src == "-":
            text = sys.stdin.read()
        else:
            try:
                text = read_text(src)
            except OSError as e:
                print("跳过 %s: %s" % (src, e), file=sys.stderr)
                continue
            if text is None:
                continue
        for f in scan_text(text, rules, allowlist):
            report.append((src, f))

    if args.format == "json":
        data = [{
            "file": src, "line": f.line, "column": f.col,
            "rule": f.rule.name, "label": f.rule.label, "preview": mask(f.value),
        } for src, f in report]
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        for src, f in report:
            name = "<stdin>" if src == "-" else src
            print("%s:%d:%d  %-16s %s  %s" % (name, f.line, f.col, f.rule.name, f.rule.label, mask(f.value)))
        if report:
            print("\n共发现 %d 处敏感信息。用 `paste-guard redact` 输出脱敏版本。" % len(report), file=sys.stderr)
        else:
            print("没有发现敏感信息。", file=sys.stderr)
    return 1 if report else 0


def cmd_redact(args, rules, allowlist):
    if args.path in (None, "-"):
        text = sys.stdin.read()
    else:
        text = read_text(args.path)
        if text is None:
            raise SystemExit("无法读取（二进制或超过 2MB）: %s" % args.path)
    findings = scan_text(text, rules, allowlist)
    result = redact_text(text, findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
    else:
        sys.stdout.write(result)
    print("已替换 %d 处。" % len(findings), file=sys.stderr)
    return 0


def cmd_demo(args, rules, allowlist):
    print("—— 原文（虚构）——")
    print(DEMO)
    findings = scan_text(DEMO, rules, allowlist)
    print("—— 扫描结果 ——")
    for f in findings:
        print("第 %d 行  %-16s %s  %s" % (f.line, f.rule.name, f.rule.label, mask(f.value)))
    print("\n—— 脱敏后 ——")
    print(redact_text(DEMO, findings))
    return 0


def cmd_rules(args, rules, allowlist):
    for r in RULES:
        print("%-16s %s" % (r.name, r.label))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="paste-guard",
        description="把文本贴给 AI 之前，先扫描密钥与个人信息，并可一键脱敏。")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--only", help="只启用这些规则，逗号分隔，如 CN_MOBILE,EMAIL")
    common.add_argument("--skip", help="跳过这些规则，逗号分隔")
    common.add_argument("--allowlist", default=".pasteguardignore",
                        help="放行清单文件，每行一个值或通配符（默认 .pasteguardignore）")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", parents=[common], help="扫描文件、目录或标准输入，发现问题时退出码为 1")
    s.add_argument("paths", nargs="*", help="文件或目录；不填则读标准输入")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("redact", parents=[common], help="输出脱敏后的文本")
    r.add_argument("path", nargs="?", help="文件；不填或 - 则读标准输入")
    r.add_argument("-o", "--output", help="写入文件而不是标准输出")
    r.set_defaults(func=cmd_redact)

    d = sub.add_parser("demo", parents=[common], help="用一段虚构样例演示效果")
    d.set_defaults(func=cmd_demo)

    l = sub.add_parser("rules", parents=[common], help="列出全部规则")
    l.set_defaults(func=cmd_rules)
    return p


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2
    rules = pick_rules(args.only, args.skip)
    allowlist = load_allowlist(args.allowlist)
    return args.func(args, rules, allowlist)


if __name__ == "__main__":
    sys.exit(main())
