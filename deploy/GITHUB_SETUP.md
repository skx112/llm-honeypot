# GitHub 环境配置说明

本文档记录本机访问 GitHub 的网络特性，以及完成发布所需的**网页端操作步骤**。
自动化部分已由 `deploy/github_env.sh` 完成，剩下的是只有账号持有者能做的操作。

---

## 一、本机网络特性（实测结论）

GitHub 在本机的可达性是**部分受限**的，这与常见的"能不能上 GitHub"印象不同，必须按实测结果设计发布路径：

| 端点 | 状态 | 用途 |
|---|---|---|
| `github.com:22` | ✅ 可用 | **git push 走这里（主通道）** |
| `ssh.github.com:443` | ✅ 可用 | SSH over 443（备用通道） |
| `api.github.com:443` | ✅ 可用 | 建仓库、元数据、Release、Actions 密钥 |
| `codeload.github.com:443` | ✅ 可用 | 下载 Release / 归档 |
| `objects.githubusercontent.com:443` | ✅ 可用 | Release 附件 |
| `github.com:443` | ❌ 被阻断 | 网页端、git over HTTPS |
| `raw.githubusercontent.com:443` | ❌ 被阻断 | Raw 文件直链 |
| `git over HTTPS` | ❌ 不可用 | 即使把域名固定到能打开首页的边缘 IP（`140.82.121.3` / `20.27.177.113` 均实测 HTTP 200），`/info/refs?service=git-upload-pack` 智能 HTTP 端点仍然超时 |

**关键结论：** 阻断是 **IP 级别**的 —— `github.com` 的 DNS 解析结果 `20.205.243.166` 的 443 端口被阻断，而同一域名的其他边缘 IP 可以正常握手。但 git 的智能 HTTP 传输另有更深的阻断，因此 **HTTPS 完全不可用，SSH 是唯一可行的 git 传输通道**。

由此产生两个配置要点：

1. 已执行 `git config --global url."git@github.com:".insteadOf "https://github.com/"`。
   任何 `https://github.com/...` 形式的远程地址会被**自动改写为 SSH**。
   这样你从别处复制来的 `git clone https://github.com/xxx/yyy.git` 命令在本机可以直接用，不会卡死。
   若某天需要临时用回 HTTPS，加 `-c url."https://github.com/".insteadOf=` 覆盖即可。

2. 不要在 `/etc/hosts` 里硬固定 GitHub 的 IP。看起来能"绕过"443 阻断，但 GitHub 边缘 IP 会轮换，硬固定会在某天静默失效，而且对 git 智能 HTTP 传输无效。SSH 走 22 端口由 DNS 正常解析即可，无需任何 hack。

---

## 二、需要你完成的操作

> ⚠️ **重要前提**：`github.com:443` 在本机被阻断，意味着**这台机器打不开 GitHub 网页**。
> 下面的网页端操作请**在你自己的电脑或手机上**完成，不要试图在服务器上打开链接。

### 步骤 1：把 SSH 公钥添加到 GitHub 账户

在**服务器上**查看公钥：

```bash
cat ~/.ssh/id_ed25519_github.pub
```

复制整行输出（以 `ssh-ed25519 ` 开头），然后**在你自己的电脑上**：

1. 打开 <https://github.com/settings/ssh/new>
2. **Title** 填一个有辨识度的名字，例如 `hw-honeypot-vm`
3. **Key type** 选 `Authentication Key`
4. **Key** 粘贴上面的整行内容
5. 点击 **Add SSH key**

> 建议在正式发布前考虑为这个密钥设置 passphrase 并改用 `ssh-agent`。
> 当前密钥无口令，是为了让本机自动化流程（提交、打标签、推送）能够无人值守运行。

### 步骤 2：验证认证

```bash
bash /data/llm-honeypot/deploy/github_env.sh --verify
```

看到 `Hi <你的用户名>! You've successfully authenticated` 即表示通道完全打通。

### 步骤 3：决定仓库信息

请确认以下四项，我据此完成初始化与发布：

| 项目 | 说明 | 示例 |
|---|---|---|
| 仓库名 | 建议简短、可检索 | `llm-honeypot` |
| 所有者 | 你的用户名，或某个组织 | `yourname` |
| 可见性 | Public / Private | `Public` |
| 开源许可证 | 建议 Apache-2.0（含专利授权，安全工具常用）或 MIT | `Apache-2.0` |

### 步骤 4：提交身份（commit 署名）

noreply 邮箱在 GitHub 设置页里有时找不到 —— 它只在开启「保持我的电子邮件地址私密」
之后才显示。但它的格式是确定的，数字 ID 可以从 `api.github.com` 查到，
所以**不需要去 UI 里翻**：

```bash
python3 deploy/github_identity.py <你的GitHub用户名>          # 只查询, 不写入
python3 deploy/github_identity.py <你的GitHub用户名> --set    # 查询并写入 git 配置
```

工具会打印你的数字 ID、推导出的 noreply 地址，并（加 `--set` 时）自动写入
`user.name` / `user.email`。

想换显示名可以加 `--name "你的名字"`。如果不想用 noreply 而想用真实邮箱：

```bash
python3 deploy/github_identity.py <用户名> --email "you@example.com" --set
python3 deploy/github_identity.py --verify "you@example.com"   # 校验归属
```

**关于 noreply 的三个要点**

1. **它不是必需的。** 直接用你已绑定并验证过的真实邮箱，提交一样会正确归属到你的账户，
   代价只是真实邮箱会出现在公开的提交元数据里。
2. **现代格式是 `<数字ID>+<用户名>@users.noreply.github.com`**，老账户的
   `<用户名>@users.noreply.github.com` 同样被识别。
3. **数字 ID 必须对。** 写错 ID 的 noreply 地址 GitHub 不认，提交会显示为"未归属"。
   用上面的 `--verify` 可以校验。

> 未绑定到账户的邮箱不会导致推送失败，但提交会显示为未归属 —— 这类问题在
> 首次提交之后很难修正（要改写历史），所以这一步值得先做对。

---

## 三、发布路径（三选一）

### 路径 A：SSH 推送（推荐，已完成配置）

环境就绪后，用发布脚本一步完成。脚本会先做前置检查，**任何一项不合格就拒绝动作**，
不会产生半成品提交：

```bash
cd /data/llm-honeypot

# 1) 只检查, 不改动任何东西
bash deploy/publish.sh --check

# 2) 检查通过后正式发布
bash deploy/publish.sh --repo <owner>/<repo> -m "Initial release"
```

脚本会依次校验：本地仓库状态、提交身份是否已配置、**敏感内容是否会被提交**
（遥测库 `var/`、日志、证书、真实 IP 字面量）、开源元文件、GitHub SSH 认证、远程地址。
手工等价命令为：

```bash
git remote add origin git@github.com:<owner>/<repo>.git
git push -u origin main
```

脚本刻意**不包含**任何破坏性操作：不做 force push、不改写历史、不删除远程分支。

### 路径 B：用 API 建仓库

`github.com:443` 被阻断，网页端在本机打不开，但 `api.github.com` 可用。
如果希望建仓库这一步也自动化，提供一个 PAT 即可：

```bash
# 需要 classic token 的 repo 权限, 或 fine-grained token 的 Administration: Read and write
curl -sS -X POST https://api.github.com/user/repos \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d '{"name":"llm-honeypot","private":false,
       "description":"Honeypot & countermeasure system against LLM-driven penetration testing",
       "license_template":"apache-2.0"}'
```

### 路径 C：在你自己电脑上推送（不推荐，仅作保底）

本机也可以只产出 `git bundle`，由你在本地克隆后推送。
缺点是后续每次更新都要来回搬运，适合作为一次性备份手段：

```bash
cd /data/llm-honeypot && git bundle create /tmp/llm-honeypot.bundle --all
```

---

## 四、关于凭据的安全提醒

- **只给最小权限**。若提供 PAT，请用 fine-grained token，只勾选目标仓库的
  `Contents: Read and write`（如走路径 B 再加 `Administration: Read and write`），
  有效期设为最短（如 7 天）。
- **用完即撤**。发布完成后立即在 <https://github.com/settings/tokens> 撤销。
- **优先用 SSH**。路径 A 不需要在本机存放任何长期令牌，密钥也可随时在 GitHub 侧删除，
  风险低于 PAT。
- 令牌一旦出现在本机的命令行参数或环境变量中，就可能留在 shell 历史与进程列表里。
  如果走路径 B，我会通过临时环境变量传递并在用后清除，但**你仍应假定它已被本机记录**，
  因此务必设置有效期并在事后撤销。

---

## 五、本机已完成的环境配置清单

- ✅ `git` 2.27.0 已安装
- ✅ 生成 ed25519 专用密钥 `~/.ssh/id_ed25519_github`（权限 600）
- ✅ `~/.ssh/config` 配置 GitHub 主/备通道，`IdentitiesOnly yes`
- ✅ `~/.ssh/known_hosts` 写入 GitHub 主机公钥，**已逐条比对官方公布指纹，全部一致**
- ✅ git 全局配置：`init.defaultBranch=main`、`push.default=simple`、
  `https://github.com/` → `git@github.com:` 自动改写
- ✅ 备用通道 `ssh.github.com:443` 实测可用
