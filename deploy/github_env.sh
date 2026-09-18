#!/usr/bin/env bash
# GitHub 环境一键配置 / 校验脚本 (幂等, 可反复执行)
#
# 背景: 本机所在的网络环境对 GitHub 有针对性限制 ——
#   github.com:443        ✗ 被阻断 (DNS 解析到的 20.205.243.166 直接被墙)
#   github.com:22         ✓ 可用  <-- git push 走这里
#   ssh.github.com:443    ✓ 可用  <-- 备用通道
#   api.github.com:443    ✓ 可用  <-- 建仓库/元数据走这里
#   git over HTTPS        ✗ 不可用 (即使固定到能打开首页的 IP, info/refs 仍超时)
# 因此本脚本把 SSH 作为唯一 git 传输通道。
#
# 用法:
#   bash deploy/github_env.sh              # 配置 + 校验
#   bash deploy/github_env.sh --verify      # 只校验, 不改动任何东西

set -uo pipefail

KEY_PATH="${GITHUB_SSH_KEY:-$HOME/.ssh/id_ed25519_github}"
SSH_CONFIG="$HOME/.ssh/config"
KNOWN_HOSTS="$HOME/.ssh/known_hosts"
VERIFY_ONLY=0
[ "${1:-}" = "--verify" ] && VERIFY_ONLY=1

# GitHub 官方公布的主机密钥指纹 (docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
OFFICIAL_FINGERPRINTS=(
  "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"   # ED25519
  "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"   # ECDSA
  "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"   # RSA
)

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'
ok()   { echo "${GREEN}  ✓${NC} $*"; }
bad()  { echo "${RED}  ✗${NC} $*"; }
warn() { echo "${YELLOW}  !${NC} $*"; }
info() { echo "${DIM}    $*${NC}"; }

FAILURES=0

echo "=============================================================="
echo " GitHub 环境配置 ($([ "$VERIFY_ONLY" -eq 1 ] && echo '仅校验' || echo '配置+校验'))"
echo "=============================================================="

# ---------- 1. 工具链 ----------
echo
echo "[1/5] 检查 SSH 工具链"
for tool in ssh ssh-keygen ssh-keyscan; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool"; else bad "$tool 缺失 (dnf install -y openssh-clients)"; FAILURES=$((FAILURES+1)); fi
done
if command -v git >/dev/null 2>&1; then ok "git $(git --version | awk '{print $3}')"; else bad "git 缺失 (dnf install -y git)"; FAILURES=$((FAILURES+1)); fi

# ---------- 2. 密钥 ----------
echo
echo "[2/5] GitHub SSH 密钥"
if [ -f "$KEY_PATH" ]; then
  ok "密钥已存在: $KEY_PATH"
  info "指纹: $(ssh-keygen -lf "$KEY_PATH.pub" 2>/dev/null | awk '{print $2}')"
elif [ "$VERIFY_ONLY" -eq 1 ]; then
  bad "密钥不存在: $KEY_PATH (去掉 --verify 重新运行即可生成)"
  FAILURES=$((FAILURES+1))
else
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  ssh-keygen -t ed25519 -C "github@$(hostname)" -f "$KEY_PATH" -N "" -q
  chmod 600 "$KEY_PATH"; chmod 644 "$KEY_PATH.pub"
  ok "已生成 ed25519 密钥: $KEY_PATH"
fi
[ -f "$KEY_PATH" ] && { chmod 600 "$KEY_PATH"; chmod 644 "$KEY_PATH.pub"; }

# ---------- 3. SSH 配置 ----------
echo
echo "[3/5] SSH 客户端配置"
if [ "$VERIFY_ONLY" -eq 0 ]; then
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  touch "$SSH_CONFIG"; chmod 600 "$SSH_CONFIG"
  if grep -q "github.com" "$SSH_CONFIG" 2>/dev/null; then
    ok "~/.ssh/config 已含 GitHub 配置, 跳过"
  else
    cat >> "$SSH_CONFIG" <<'SSHEOF'

# === GitHub (由 llm-honeypot 的 github_env.sh 写入) ===
Host github.com
    HostName github.com
    Port 22
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes
    ServerAliveInterval 30
    ServerAliveCountMax 4
    TCPKeepAlive yes
# 备用通道: SSH over 443
Host github-443
    HostName ssh.github.com
    Port 443
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes
    ServerAliveInterval 30
SSHEOF
    ok "已写入 ~/.ssh/config"
  fi
else
  [ -f "$SSH_CONFIG" ] && grep -q "github.com" "$SSH_CONFIG" && ok "~/.ssh/config 含 GitHub 配置" || { bad "~/.ssh/config 缺少 GitHub 配置"; FAILURES=$((FAILURES+1)); }
fi

# ---------- 4. 主机密钥校验 (防中间人) ----------
echo
echo "[4/5] 校验 GitHub 主机公钥指纹"
scanned=$(timeout 25 ssh-keyscan -t rsa,ecdsa,ed25519 github.com 2>/dev/null)
if [ -z "$scanned" ]; then
  bad "ssh-keyscan 无响应, 请检查 github.com:22 连通性"
  FAILURES=$((FAILURES+1))
else
  mismatch=0
  while read -r fp; do
    hit=0
    for official in "${OFFICIAL_FINGERPRINTS[@]}"; do
      [ "$fp" = "$official" ] && hit=1
    done
    [ "$hit" -eq 0 ] && { bad "指纹不匹配: $fp"; mismatch=$((mismatch+1)); }
  done < <(echo "$scanned" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  if [ "$mismatch" -eq 0 ]; then
    ok "全部主机公钥指纹与 GitHub 官方公布值一致, 无中间人风险"
    if [ "$VERIFY_ONLY" -eq 0 ]; then
      touch "$KNOWN_HOSTS"; chmod 600 "$KNOWN_HOSTS"
      echo "$scanned" >> "$KNOWN_HOSTS"
      sort -u "$KNOWN_HOSTS" -o "$KNOWN_HOSTS"
      ok "已写入 ~/.ssh/known_hosts ($(wc -l < "$KNOWN_HOSTS") 条)"
    fi
  else
    FAILURES=$((FAILURES+1))
  fi
fi

# ---------- 5. 连通性与认证 ----------
echo
echo "[5/5] 连通性与认证状态"
if [ "$VERIFY_ONLY" -eq 0 ]; then
  git config --global init.defaultBranch main
  git config --global pull.rebase false
  git config --global push.default simple
  git config --global core.autocrlf input
  git config --global core.quotepath false
  git config --global fetch.prune true
  # 关键: 本机 git over HTTPS 不可用, 把 https 远程自动改写为 SSH
  git config --global url."git@github.com:".insteadOf "https://github.com/"
  ok "已写入 git 全局配置"
fi

sshd_out=$(timeout 25 ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes git@github.com 2>&1)
if echo "$sshd_out" | grep -qi "successfully authenticated"; then
  ok "SSH 认证成功: $(echo "$sshd_out" | head -1)"
  AUTHED=1
elif echo "$sshd_out" | grep -qi "permission denied"; then
  warn "传输正常, 但公钥尚未注册到 GitHub 账户"
  info "这是最后一步, 需要你在 GitHub 网页端完成 —— 见 deploy/GITHUB_SETUP.md"
  AUTHED=0
else
  bad "SSH 连接异常: $(echo "$sshd_out" | head -2)"
  FAILURES=$((FAILURES+1))
  AUTHED=0
fi

# 备用通道
alt_out=$(timeout 20 ssh -T -o BatchMode=yes -o StrictHostKeyChecking=no -p 443 git@ssh.github.com 2>&1)
if echo "$alt_out" | grep -qiE "successfully authenticated|permission denied"; then
  ok "备用通道 ssh.github.com:443 可用"
else
  warn "备用通道 ssh.github.com:443 不可用 ($(echo "$alt_out" | head -1))"
fi

# ---------- 汇总 ----------
echo
echo "=============================================================="
if [ "$FAILURES" -gt 0 ]; then
  echo "${RED}环境存在问题: $FAILURES 项失败${NC}"
elif [ "${AUTHED:-0}" -eq 1 ]; then
  echo "${GREEN}GitHub 环境就绪 ✓${NC}"
else
  echo "${YELLOW}环境配置完成, 待完成 1 项网页端操作:${NC}"
  echo
  echo "  把下面这段公钥添加到 GitHub -> Settings -> SSH and GPG keys:"
  echo
  echo "${DIM}  ------------------------------------------------------------${NC}"
  cat "$KEY_PATH.pub" 2>/dev/null | sed 's/^/  /'
  echo "${DIM}  ------------------------------------------------------------${NC}"
  echo
  echo "  添加后重新运行本脚本校验: bash deploy/github_env.sh --verify"
fi
echo "=============================================================="
exit $([ "$FAILURES" -eq 0 ] && echo 0 || echo 1)
