# paste-guard

把日志、配置、报错贴给 ChatGPT / Claude / 豆包 / Kimi 之前，先跑一下 `paste-guard`：它会找出里面的密钥、密码、身份证号、手机号、银行卡号、车牌、邮箱，并换成 `[CN_MOBILE_1]` 这样的占位符。

- 单文件、零依赖，只要 Python 3.8+
- 针对中文场景：身份证带校验位验证，银行卡走 Luhn 校验，手机号支持 `+86`、带横杠写法，车牌含新能源
- 同一个值不管写成 `138-0013-8000` 还是 `13800138000`，都替换成同一个占位符，AI 仍能看懂“这两处是同一个人”
- 能当 pre-commit 钩子，或在 CI 里用退出码拦截

> English: a zero-dependency CLI that finds and redacts secrets and Chinese PII (ID card with checksum, mobile, bank card with Luhn, license plate) before you paste text into an LLM.

## 安装

```bash
pip install git+https://github.com/temptation2017/paste-guard.git
```

不想安装也行，直接下载单个文件：

```bash
curl -O https://raw.githubusercontent.com/temptation2017/paste-guard/main/paste_guard.py
python3 paste_guard.py demo
```

## 先看效果

```bash
paste-guard demo
```

输出（样例数据全部虚构，身份证号取自国家标准里的示例）：

```text
—— 扫描结果 ——
第 2 行  URL_CREDENTIAL   URL 内嵌账号密码  hu*******ss
第 3 行  AWS_ACCESS_KEY   AWS Access Key  AKIA************MPLE
第 4 行  PASSWORD_ASSIGN  密码/密钥赋值  S3*******o!
第 5 行  CN_MOBILE        手机号  138-*****8000
第 5 行  EMAIL            邮箱  zhan************.com
第 6 行  CN_ID            身份证号  1101**********002X
第 6 行  CN_PLATE         车牌号  京A****45
第 7 行  CN_MOBILE        手机号  13*******00

—— 脱敏后 ——
# 这是一段虚构的示例，所有数据都不真实
DATABASE_URL=postgres://admin:[URL_CREDENTIAL_1]@db.example.com:5432/app
aws_key = [AWS_ACCESS_KEY_1]
password: [PASSWORD_ASSIGN_1]
联系人：张三，手机 [CN_MOBILE_1]，邮箱 [EMAIL_1]
身份证 [CN_ID_1]，车牌 [CN_PLATE_1]
备注：手机 [CN_MOBILE_1] 与上面是同一个号码
```

## 用法

### 扫描

```bash
paste-guard scan app.log            # 单个文件
paste-guard scan ./config ./logs    # 目录会递归，自动跳过 .git、node_modules、二进制和超过 2MB 的文件
cat error.txt | paste-guard scan    # 标准输入
paste-guard scan --format json src/ # JSON 输出，预览值已打码
```

有发现时退出码为 `1`，没有为 `0`，可以直接放进脚本或 CI。

### 脱敏

```bash
paste-guard redact app.log > app.safe.log
paste-guard redact app.log -o app.safe.log
```

### 剪贴板一条龙

复制好要贴的内容，然后：

```bash
# macOS
pbpaste | paste-guard redact | pbcopy

# Linux（X11）
xclip -o -sel clip | paste-guard redact | xclip -sel clip

# Windows PowerShell
Get-Clipboard | paste-guard redact | Set-Clipboard
```

再粘贴到 AI 对话框里就是脱敏后的版本。

### 只开或关掉某些规则

```bash
paste-guard rules                         # 查看全部规则名
paste-guard scan --only CN_MOBILE,CN_ID x.txt
paste-guard redact --skip EMAIL x.txt
```

### 放行清单

公开的客服邮箱、官方文档里的示例 Key 不想被拦，可以在当前目录建 `.pasteguardignore`，每行一个值，支持 `*` `?` 通配符：

```text
# 公开邮箱
*@example.com
AKIAIOSFODNN7EXAMPLE
```

也可以用 `--allowlist 路径` 指定别的文件。仓库里有一份 `.pasteguardignore.example`。

### 当 pre-commit 钩子

在你项目的 `.pre-commit-config.yaml` 里加：

```yaml
repos:
  - repo: https://github.com/temptation2017/paste-guard
    rev: main
    hooks:
      - id: paste-guard
```

## 支持的规则

| 规则 | 说明 |
| --- | --- |
| `PRIVATE_KEY` | PEM 私钥块 |
| `AWS_ACCESS_KEY` | `AKIA` / `ASIA` 开头的 Access Key |
| `GITHUB_TOKEN` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` 与 `github_pat_` |
| `ANTHROPIC_KEY` / `OPENAI_KEY` | `sk-ant-` / `sk-` `sk-proj-` 开头的 Key |
| `SLACK_TOKEN` | `xoxb-` 等 |
| `GOOGLE_API_KEY` | `AIza` 开头 |
| `JWT` | 三段式 `eyJ...` |
| `URL_CREDENTIAL` | `scheme://user:密码@host` 里的密码部分 |
| `PASSWORD_ASSIGN` | `password=`、`secret:`、`api_key=`、`密码：` 后面的值 |
| `CN_ID` | 18 位身份证号，校验位不对的不算 |
| `BANK_CARD` | 16–19 位，需通过 Luhn 校验 |
| `CN_MOBILE` | 大陆手机号，支持 `+86`、空格、横杠 |
| `EMAIL` | 邮箱地址 |
| `CN_PLATE` | 大陆车牌，含新能源绿牌 |

## 限制

- 规则基于正则和校验算法，不是万能的：姓名、住址、公司内部项目名这类没有固定格式的信息识别不了，贴之前还是要自己扫一眼。
- `PASSWORD_ASSIGN` 靠关键字判断，偶尔会把 `password: required` 这类说明文字也当成密码。
- 它不替代仓库级的密钥扫描（如 gitleaks、GitHub Secret Scanning），更适合“贴给 AI 前最后过一遍”。
- 默认只处理 UTF-8 文本。

## 后续可以改进

- 可选的“还原”功能：把 AI 回复里的占位符换回原值（映射表只留在本地）
- 自定义规则文件（YAML/JSON）
- 浏览器扩展，在网页输入框粘贴时自动提示

## 开发

```bash
python3 -m unittest discover -s tests -v
```

测试里的假凭据都是运行时拼出来的，仓库里不放任何真实或长得像真的密钥。

## 许可

MIT
