# dsh-poison-guard — DeepSeek Harness 插件投毒检测（第一道防线）

在 `dsh plugin add` 之前，先扫一遍插件源码，把小白看不出来的投毒特征标出来。

## 先说清楚边界（这不是免责，是安全常识）

静态扫描不等于安全保证。任何"找模式"的工具都能被刻意混淆的恶意代码绕过——这是不可判定的，不是这个工具做得不够好。所以它拦住的是"明显/粗心的投毒"（读密钥、动态 eval、安装脚本联网、读 .ssh 等），这是第一道防线；真正的边界是 dsh 自带的沙箱——未验证的插件永远别开 danger-full-access；最后一层是来源信誉——优先用有 verified 标记、有维护者、来源明确的插件。

## 能查什么

| 级别 | 检测 |
|---|---|
| HIGH | 读 SSH/AWS/GPG 私钥、凭证名 + 联网外发组合、eval / new Function 动态执行 |
| MEDIUM | 联网请求、child_process 执行命令、postinstall/prepare 等安装脚本 |
| LOW | 读 process.env、base64 混淆 |

## 用法

```sh
dsh-poison-guard scan ./some-plugin
dsh-poison-guard scan ./some-plugin --json
dsh plugin --profile web add github:zoahdev/dsh-poison-guard
```

装进 dsh 后，agent 多了 `plugin_scan` 工具，可以扫任意插件目录。

## 结果示例

```text
MALICIOUS  1 high / 2 medium / 1 low finding(s)
[HIGH] exfil-combo  (whole plugin):0
       reads credentials AND makes network requests — classic exfiltration
[HIGH] exfil-secrets  lib/index.js:12
       references credential-style names; combined with network this is exfiltration
```

退出码：0 = CLEAN，1 = 有发现（可接 CI 门禁）。

它不会"拦住所有投毒"，但它能让小白在装插件前，多一道他们自己根本不会做的检查。

---

# dsh-poison-guard — supply-chain poison scanner for DeepSeek Harness plugins

A first-line-of-defense, pre-install static scanner: flags credential exfiltration, dynamic eval, install-time scripts, and network egress. Heuristic, not a security guarantee — obfuscated code can bypass it; the real boundary is the harness sandbox.

```sh
dsh-poison-guard scan ./plugin-dir --json
dsh plugin --profile web add github:zoahdev/dsh-poison-guard
```
