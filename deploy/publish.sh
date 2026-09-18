#!/usr/bin/env bash
# 发布脚本: 把当前工作区提交并推送到 GitHub。
#
# 设计原则: 先做完整前置检查再动作, 且绝不执行任何破坏性操作
# (不 force push、不改写历史、不删除远程分支)。
#
# 用法:
#   bash deploy/publish.sh --check              # 只做前置检查
#   bash deploy/publish.sh --repo owner/name    # 检查 + 首次提交 + 推送
#   bash deploy/publish.sh --repo owner/name -m "提交信息"
#
# 若远程仓库还不存在, 本机又打不开 github.com 网页端(见 GITHUB_SETUP.md 的网络实测),
# 可以用 PAT 让脚本通过 api.github.com 建仓库:
#   GITHUB_TOKEN=<fine-grained-token> bash deploy/publish.sh \
#       --repo owner/name --create-repo
# 令牌从环境变量读取, 不经过命令行参数 —— 避免它留在 shell 历史与进程列表里。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REPO=""
MESSAGE=""
CHECK_ONLY=0
CREATE_REPO=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="${2:-}"; shift 2;;
    --check) CHECK_ONLY=1; shift;;
    --create-repo) CREATE_REPO=1; shift;;
    -m|--message) MESSAGE="${2:-}"; shift 2;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "未知参数: $1"; exit 2;;
  esac
done

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'
ok()   { echo "${GREEN}  ✓${NC} $*"; }
bad()  { echo "${RED}  ✗${NC} $*"; }
warn() { echo "${YELLOW}  !${NC} $*"; }
FAIL=0

echo "=============================================================="
echo " 发布前检查"
echo "=============================================================="

# ---------- 1. 仓库状态 ----------
echo
echo "[1/6] 本地仓库"
if [ ! -d .git ]; then
  if [ "$CHECK_ONLY" -eq 1 ]; then bad "尚未 git init"; FAIL=1
  else
    # 注意: git < 2.28 不支持 `git init -b` 也不认 init.defaultBranch,
    # 因此显式把 HEAD 指向 main, 保证各版本行为一致。
    git init -q
    git symbolic-ref HEAD refs/heads/main
    ok "已初始化仓库 (分支 main)"
  fi
else
  ok "仓库已存在, 当前分支 $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
fi

# ---------- 2. 提交身份 ----------
echo
echo "[2/6] 提交身份"
NAME=$(git config user.name 2>/dev/null || true)
EMAIL=$(git config user.email 2>/dev/null || true)
if [ -n "$NAME" ] && [ -n "$EMAIL" ]; then
  ok "user.name=$NAME"
  ok "user.email=$EMAIL"
else
  bad "提交身份未配置 (首次提交前必须设置, 否则历史里的署名是错的)"
  echo "${DIM}    git config --global user.name  \"Your Name\"${NC}"
  echo "${DIM}    git config --global user.email \"<ID>+<user>@users.noreply.github.com\"${NC}"
  FAIL=1
fi

# ---------- 3. 敏感内容检查 ----------
echo
echo "[3/6] 敏感内容检查 (遥测库/证书/真实 IP 是否会被提交)"
blocked=0
while IFS= read -r path; do
  bad "不应提交: $path"
  blocked=$((blocked+1))
done < <(git ls-files --cached --others --exclude-standard 2>/dev/null | grep -E '\.(db|db-wal|log|pem|key|crt)$|^(var|logs|out|reports|rules)/' || true)
if [ "$blocked" -eq 0 ]; then ok "未发现遥测数据/日志/证书类文件"; else FAIL=1; fi

if [ -n "$NAME" ] && [ -n "$EMAIL" ]; then
  # IP 泄露检查: 目标是发现"操作者的真实资产地址被写进开源仓库"。
  # 必须能自动区分保留段与真实公网地址 —— 一个总在报警的检查会训练人忽略它。
  # 已知的良性外部地址(测试保留段、公共 DNS 探测目标、GitHub 自身边缘 IP)
  # 在此显式归类, 不计入告警。
  ip_out=$(python3 - <<'PYIP' 2>&1
import os, re, subprocess, sys

TEST_NET = {"192.0.2.": "TEST-NET-1", "198.51.100.": "TEST-NET-2",
            "203.0.113.": "TEST-NET-3"}
PUBLIC_DNS = {"1.1.1.1": "Cloudflare 公共 DNS(连通性探测目标)",
              "8.8.8.8": "Google 公共 DNS(连通性探测目标)",
              "2.2.2.2": "通用测试地址"}

def reserved(ip):
    p = [int(x) for x in ip.split(".")]
    if p[0] == 0: return "保留 0/8"
    if p[0] == 10: return "私网 RFC1918"
    if p[0] == 127: return "回环"
    if p[0] == 169 and p[1] == 254: return "链路本地"
    if p[0] == 172 and 16 <= p[1] <= 31: return "私网 RFC1918"
    if p[0] == 192 and p[1] == 168: return "私网 RFC1918"
    if p[0] == 100 and 64 <= p[1] <= 127: return "CGNAT 保留段 RFC6598"
    if p[0] >= 224: return "组播/保留"
    return None

def benign(ip):
    if ip in PUBLIC_DNS: return PUBLIC_DNS[ip]
    for prefix, label in TEST_NET.items():
        if ip.startswith(prefix): return label + " (RFC5737)"
    p = [int(x) for x in ip.split(".")]
    # GitHub 自身边缘 IP: 本项目的网络实测文档记录的是 GitHub 基础设施事实,
    # 不是操作者资产。范围覆盖 GitHub 公布的常见网段。
    if (p[0] == 20 and p[1] in (27, 200, 205, 233, 240, 250)) or \
       (p[0] == 140 and p[1] in (82, 83)):
        return "GitHub 边缘 IP(网络实测记录)"
    return None

# 前置断言排除版本号形态(如 UA 里的 Chrome/124.0.0.0 会被误当成 IP)
IP_RE = re.compile(r"(?<![\dA-Za-z/._])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")

try:
    tracked = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
    ).decode("utf-8", "replace").split()
except Exception:
    tracked = []

benign_hits, suspicious = {}, {}
for path in tracked:
    if not os.path.isfile(path) or path.endswith((".png", ".db", ".ico")):
        continue
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        continue
    for ip in IP_RE.findall(text):
        label = reserved(ip) or benign(ip)
        if label:
            benign_hits.setdefault(label, set()).add(ip)
        else:
            suspicious.setdefault(ip, set()).add(path)

total = sum(len(v) for v in benign_hits.values())
print("BENIGN_COUNT=%d" % total)
if suspicious:
    for ip in sorted(suspicious):
        print("! %s  <- %s" % (ip, ", ".join(sorted(suspicious[ip])[:4])))
else:
    print("分类明细: " + "; ".join(
        "%s×%d" % (k, len(v)) for k, v in sorted(benign_hits.items())))
PYIP
)
  if echo "$ip_out" | grep -q '^! '; then
    warn "以下 IP 字面量不在保留段/已知良性范围内, 提交前请确认非真实资产:"
    echo "$ip_out" | grep '^! ' | sed 's/^! /      /'
    FAIL=1
  else
    count=$(echo "$ip_out" | grep '^BENIGN_COUNT=' | cut -d= -f2)
    detail=$(echo "$ip_out" | grep '^分类明细:' | sed 's/^分类明细: //')
    ok "IP 字面量共 $count 处, 全部为保留段/测试保留段/已知外部地址"
    echo "$detail" | tr ';' '\n' | sed 's/^ *//' | grep -v '^$' | sed 's/^/      · /'
  fi
fi

# ---------- 4. 开源元文件 ----------
echo
echo "[4/6] 开源元文件"
for f in README.md LICENSE .gitignore; do
  [ -f "$f" ] && ok "$f" || { warn "$f 缺失"; }
done

# ---------- 5. GitHub 认证 ----------
echo
echo "[5/6] GitHub SSH 认证"
ssh_out=$(timeout 25 ssh -T -o BatchMode=yes git@github.com 2>&1 || true)
if echo "$ssh_out" | grep -qi "successfully authenticated"; then
  ok "$(echo "$ssh_out" | head -1)"
  GH_USER=$(echo "$ssh_out" | sed -n 's/^Hi \([^!]*\)!.*/\1/p')
  [ -n "${GH_USER:-}" ] && ok "GitHub 账户: $GH_USER"
else
  bad "SSH 认证未通过 —— 需先在 GitHub 网页端注册公钥 (见 deploy/GITHUB_SETUP.md)"
  echo "${DIM}    公钥内容:${NC}"
  sed 's/^/      /' ~/.ssh/id_ed25519_github.pub 2>/dev/null || true
  FAIL=1
fi

# ---------- 5.5 按需创建远程仓库 ----------
if [ "$CREATE_REPO" -eq 1 ] && [ -n "$REPO" ]; then
  echo
  echo "[5.5/6] 创建远程仓库"
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    warn "未提供 GITHUB_TOKEN, 跳过建仓库"
    info "建仓库需要认证。两种方式任选:"
    info "  1) 在你自己设备上打开 https://github.com/new 建一个空仓库"
    info "     (不要勾选 README / .gitignore / license, 否则首次推送会被拒)"
    info "  2) 提供 fine-grained PAT(需 Administration: Read and write)后重跑本命令"
  else
    OWNER="${REPO%%/*}"
    NAME="${REPO##*/}"
    # 先看是否已存在, 避免重复创建报错
    EXISTS=$(timeout 20 curl -sS -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/repos/$OWNER/$NAME" 2>/dev/null || echo "000")
    if [ "$EXISTS" = "200" ]; then
      ok "仓库已存在: $REPO"
    else
      RESPONSE=$(timeout 30 curl -sS -X POST https://api.github.com/user/repos \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -d "{\"name\":\"$NAME\",\"private\":false,\
\"description\":\"Honeypot and countermeasure system against LLM-driven penetration testing\",\
\"has_issues\":true,\"has_wiki\":false,\"auto_init\":false}" 2>&1)
      if echo "$RESPONSE" | grep -q '"full_name"'; then
        ok "已创建仓库: $REPO"
        info "注意: 使用 auto_init=false 创建, 远程没有任何提交 —— 首次推送不会冲突"
      else
        bad "建仓库失败: $(echo "$RESPONSE" | head -c 300)"
        info "常见原因: 令牌权限不足(需要 Administration: Read and write)"
        info "         或令牌已过期 / 未勾选目标账户"
        FAIL=$((FAIL+1))
      fi
    fi
  fi
fi

# ---------- 6. 远程配置 ----------
echo
echo "[6/6] 远程仓库"
if [ -n "$REPO" ]; then
  EXPECTED="git@github.com:$REPO.git"
  if git remote get-url origin >/dev/null 2>&1; then
    CURRENT=$(git remote get-url origin)
    if [ "$CURRENT" = "$EXPECTED" ]; then ok "origin = $CURRENT"
    else warn "origin 当前为 $CURRENT, 将改为 $EXPECTED"; [ "$CHECK_ONLY" -eq 0 ] && git remote set-url origin "$EXPECTED"; fi
  else
    [ "$CHECK_ONLY" -eq 0 ] && { git remote add origin "$EXPECTED"; ok "已设置 origin = $EXPECTED"; } || ok "将设置 origin = $EXPECTED"
  fi
else
  warn "未指定 --repo owner/name, 跳过远程配置"
fi

# ---------- 汇总 ----------
echo
echo "=============================================================="
if [ "$FAIL" -gt 0 ]; then
  echo "${RED}前置检查未通过, 已停止。修好上面标 ✗ 的项再执行。${NC}"
  exit 1
fi
echo "${GREEN}前置检查通过${NC}"

if [ "$CHECK_ONLY" -eq 1 ]; then exit 0; fi
if [ -z "$REPO" ]; then
  echo "下一步: bash deploy/publish.sh --repo <owner>/<repo>"
  exit 0
fi

# ---------- 执行提交与推送 ----------
echo
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  git add -A
  staged=$(git diff --cached --name-only | wc -l)
  [ -z "$MESSAGE" ] && MESSAGE="Initial release: LLM-agent-aware honeypot & countermeasure system"
  git commit -q -m "$MESSAGE"
  ok "已创建首次提交 (共 $staged 个文件)"
else
  if [ -n "$(git status --porcelain)" ]; then
    git add -A
    [ -z "$MESSAGE" ] && MESSAGE="Update $(date +%Y-%m-%d)"
    git commit -q -m "$MESSAGE"
    ok "已创建提交"
  else
    ok "工作区干净, 无需提交"
  fi
fi

echo
echo "推送到 $REPO ..."
if git push -u origin main 2>&1 | sed 's/^/  /'; then
  echo
  echo "${GREEN}发布成功${NC}"
else
  echo
  echo "${RED}推送失败${NC}"
  echo "${DIM}  若提示仓库不存在, 请先在 GitHub 建库; 本机 github.com:443 被阻断,"${NC}
  echo "${DIM}  网页端请在你自己的电脑上打开, 或用 api.github.com 建库 (见 GITHUB_SETUP.md).${NC}"
  exit 1
fi
