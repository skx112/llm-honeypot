#!/usr/bin/env bash
# 蜜罐隔离加固: 出站拒绝 + 隔离自检
#
# 为什么这一步不可跳过
# --------------------
# 蜜罐的宿命是被攻破 —— 设计必须假设这一点。一台被攻破且能自由出站的蜜罐会变成:
#   · 攻击者的跳板, 用来横向进入你的真实网段
#   · 攻击者的 C2 节点与扫描源(以你的 IP 对外攻击, 你还要为此承担责任)
#   · 攻击者的数据中转站
#
# 本脚本把"蜜罐只应被动接收"这条设计约束**在系统层面强制执行**: 即使蜜罐进程
# 本身被完全控制, 它也无法主动外连。这同时也是对"本项目不主动连接攻击方主机"
# 这一承诺的技术保证 —— 承诺写在文档里没有用, 写在防火墙里才有用。
#
# 用法:
#   sudo bash deploy/isolate.sh --check      # 只检查当前状态, 不做任何变更
#   sudo bash deploy/isolate.sh --apply      # 应用出站拒绝规则
#   sudo bash deploy/isolate.sh --revert     # 撤销(仅在需要临时放行时)
#
# 注意: 应用后本机将无法主动访问外网。如果你需要远程管理这台机器, 请确认
# **入站**管理通道(如 SSH)不在丢弃范围内, 并且你已有带外管理手段。

set -uo pipefail

TABLE="cogtrap_isolate"
MODE="${1:---check}"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'
ok()   { echo "${GREEN}  ✓${NC} $*"; }
bad()  { echo "${RED}  ✗${NC} $*"; }
warn() { echo "${YELLOW}  !${NC} $*"; }
info() { echo "${DIM}    $*${NC}"; }

FAIL=0

echo "=============================================================="
echo " CogTrap 蜜罐隔离加固 ($MODE)"
echo "=============================================================="

if [ "$(id -u)" -ne 0 ]; then
  bad "需要 root 权限(操作 nftables)"
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  bad "系统未安装 nft (dnf install -y nftables)"
  exit 1
fi

# ---------- 变更前先备份 ----------
BACKUP_DIR="/var/backups/cogtrap-isolate"
if [ "$MODE" = "--apply" ]; then
  mkdir -p "$BACKUP_DIR"
  nft list ruleset > "$BACKUP_DIR/ruleset-before-$(date +%Y%m%d-%H%M%S).nft" 2>/dev/null
  info "已备份当前规则集到 $BACKUP_DIR"
fi

# ---------- 检查项 ----------
echo
echo "[1/5] 出站策略"

existing=$(nft list table inet "$TABLE" 2>/dev/null)
if [ -n "$existing" ]; then
  ok "隔离表 inet $TABLE 已存在"
else
  if [ "$MODE" = "--check" ]; then
    warn "尚未应用出站拒绝规则(蜜罐当前可以主动外连)"
    FAIL=1
  fi
fi

echo
echo "[2/5] 关键安全前提(无法自动验证, 请人工确认)"
info "· 蜜罐是否部署在独立网段/VLAN, 与真实资产之间无双向路由?"
info "· 管理通道(SSH 等)是否走带外或独立管理网?"
info "· 系统内是否存在可用的真实凭据(应为零)?"
info "· 遥测库是否有单向外发通道, 以保证被攻破后证据仍完整?"

echo
echo "[3/5] 当前入站监听"
ss -ltn 2>/dev/null | awk 'NR>1 {print "    " $4}' | sort -u | head -12
warn "确认上面每个监听端口都是有意暴露的诱饵; 管理端口不要出现在公网网卡上"

echo
echo "[4/5] 检查是否已有真实凭据残留(常见疏漏)"
leaks=0
for f in "$HOME/.aws/credentials" "$HOME/.ssh/id_rsa" "$HOME/.git-credentials" \
         "$HOME/.netrc" "/etc/cogtrap/secrets.json"; do
  if [ -f "$f" ]; then
    bad "发现疑似真实凭据文件: $f  —— 必须移出蜜罐主机"
    leaks=$((leaks+1))
  fi
done
if [ "$leaks" -eq 0 ]; then
  ok "未发现常见真实凭据文件"
else
  FAIL=1
fi

echo
echo "[5/5] 蜜罐内不应存在出站工具链(可选加固)"
for tool in ssh scp nc ncat socat curl wget python3 git; do
  if command -v "$tool" >/dev/null 2>&1; then
    info "存在 $tool (蜜罐进程若被控制可用于出站; 出站 DROP 是第一道防线, 移除工具是第二道)"
  fi
done

# ---------- 动作 ----------
if [ "$MODE" = "--apply" ]; then
  echo
  echo "应用出站拒绝规则..."
  # 说明:
  #   - 放行 loopback 与已建立连接(否则连正常回包都收不到)
  #   - 丢弃所有新建出站连接, 覆盖 tcp/udp
  #   - 只作用于 output 链, 不影响入站诱饵
  nft -f - <<'NFT' || { bad "规则应用失败"; exit 1; }
table inet cogtrap_isolate {
    chain output_guard {
        type filter hook output priority filter; policy accept;

        # 回环与已建立连接必须放行
        oifname "lo" accept
        ct state established,related accept

        # DNS 单独放行会在被攻破时被用于隧道, 因此这里一并拒绝;
        # 若蜜罐需要解析域名, 改用 hosts 文件静态配置。
        meta l4proto { tcp, udp } ct state new drop comment "cogtrap-isolate-outbound"
    }
}
NFT
  if [ $? -eq 0 ]; then
    ok "出站拒绝已生效"
    echo
    echo "验证:"
    if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/1.1.1.1/443' 2>/dev/null; then
      bad "出站仍可连通 —— 规则未生效, 请人工核查"
    else
      ok "出站测试: 连接被拒绝(符合预期)"
    fi
    echo
    info "撤销: sudo bash deploy/isolate.sh --revert"
    info "注意: 本机现已无法主动访问外网。需要临时放行时先 --revert。"
  fi
elif [ "$MODE" = "--revert" ]; then
  echo
  nft delete table inet "$TABLE" 2>/dev/null && ok "已撤销隔离规则" || warn "隔离表不存在"
elif [ "$MODE" = "--check" ]; then
  if [ -n "$existing" ]; then
    echo
    nft list table inet "$TABLE" | sed 's/^/    /'
  fi
else
  bad "未知参数: $MODE"
  sed -n '2,20p' "$0"
  exit 2
fi

echo
echo "=============================================================="
if [ "$MODE" = "--check" ] && [ "$FAIL" -gt 0 ]; then
  echo "${YELLOW}检查发现待处理项。应用隔离: sudo bash deploy/isolate.sh --apply${NC}"
  exit 1
fi
echo "${GREEN}完成${NC}"
echo "=============================================================="
