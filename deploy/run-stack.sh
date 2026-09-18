#!/usr/bin/env bash
# CogTrap hardened 容器栈: 一条命令在 docker/podman 上起完整部署。
#
# 用法:
#   ./deploy/run-stack.sh start [实例根目录]   # 默认 /data/cogtrap
#   ./deploy/run-stack.sh stop  [实例根目录]
#   ./deploy/run-stack.sh status[实例根目录]
#
# 需要的目录结构(由 cogtrap generate 产出 + 本脚本自动补齐):
#   $ROOT/node-a/{config.json,instance.json,scenario.json}
#   $ROOT/node-b/...   $ROOT/hub/{token,env}   $ROOT/receiver/
#
# 硬化参数(每容器):
#   --read-only               根文件系统只读(实例卷除外)
#   --cap-drop=ALL            零 capabilities —— 全部监听端口 >1024, 根本不需要特权
#   --security-opt no-new-privileges
#   --pids-limit / --memory   资源上限, 防拖滞反噬与 fork 炸弹
#   --network host            保留回环互通(hub/webhook/仪表盘只听 127.0.0.1);
#                             网络隔离由宿主内核兜底(见 deploy/README: 按用户出站封锁)
#
# 本脚本同时兼容 podman(优先, 支持 rootless)与 docker。

set -euo pipefail

RUNTIME="$(command -v podman || command -v docker)"
[ -n "$RUNTIME" ] || { echo "未找到 podman/docker"; exit 1; }
RUNTIME_NAME="$(basename "$RUNTIME")"

ROOT="${2:-/data/cogtrap}"
IMAGE="${COGTRAP_IMAGE:-cogtrap:latest}"
HUB_PORT="${HUB_PORT:-9443}"

# cgroup 类限制(--memory/--pids-limit)只在 root 运行时加: rootless podman
# 在未委派 cgroup 的环境里设不了内存上限(实测会 OCI 报错); rootless 场景
# 的资源上限交给 systemd 单元层的 MemoryMax/TasksMax。
CGROUP_LIMITS=""; USERNS=""
if [ "$(id -u)" -eq 0 ]; then
  CGROUP_LIMITS="--pids-limit 256 --memory=512m"
else
  # rootless: --user 0:0 = 容器内名义 root 仅映射到宿主非特权用户;
  # 配合 --cap-drop=ALL 权限为零, 且实例卷属主(宿主用户)天然可写。
  # (keep-id 在镜像缺少对应 uid 时会映射成镜像默认用户, 实测踩过)
  USERNS="--user 0:0"
fi
HARDEN="--read-only --tmpfs /tmp:rw,size=16m --cap-drop=ALL \
  --security-opt no-new-privileges $CGROUP_LIMITS $USERNS \
  --network host"

# rootless podman 在 systemd 系统单元里需要 XDG_RUNTIME_DIR
if [ "$RUNTIME_NAME" = podman ] && [ "$(id -u)" -ne 0 ]; then
  export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
fi

cmd_node() {  # $1=名称 $2=目录
  exec "$RUNTIME" run --rm --name "cogtrap-$1" $HARDEN \
    -v "$ROOT/$2:/app/instance:Z" \
    -w /opt/cogtrap "$IMAGE" \
    --config /app/instance/config.json serve \
    --instance /app/instance/instance.json --scenario /app/instance/scenario.json
}

case "${1:-}" in
  start)
    mkdir -p "$ROOT"/{hub,receiver}
    # 1) SOC 接收端(webhook 落盘)
    "$RUNTIME" run -d --name cogtrap-receiver $HARDEN \
      -v "$ROOT/receiver:/app/instance:Z" \
      -w /opt/cogtrap --entrypoint python3 "$IMAGE" \
      /opt/cogtrap/tools/soc_receiver.py \
        --listen 127.0.0.1:8898 --out /app/instance/alerts.jsonl

    # 2) 聚合 hub
    TOKEN="$(cat "$ROOT/hub/token" 2>/dev/null || { echo "缺少 $ROOT/hub/token"; exit 1; })"
    "$RUNTIME" run -d --name cogtrap-hub $HARDEN \
      -v "$ROOT/hub:/app/instance:Z" \
      -w /opt/cogtrap "$IMAGE" \
      hub --db /app/instance/hub.db --host 127.0.0.1 --port "$HUB_PORT" --token "$TOKEN"

    # 3) 双蜜罐节点
    "$RUNTIME" run -d --name cogtrap-node-a $HARDEN \
      -v "$ROOT/node-a:/app/instance:Z" \
      -w /opt/cogtrap "$IMAGE" \
      --config /app/instance/config.json serve \
      --instance /app/instance/instance.json --scenario /app/instance/scenario.json
    "$RUNTIME" run -d --name cogtrap-node-b $HARDEN \
      -v "$ROOT/node-b:/app/instance:Z" \
      -w /opt/cogtrap "$IMAGE" \
      --config /app/instance/config.json serve \
      --instance /app/instance/instance.json --scenario /app/instance/scenario.json
    echo "栈已启动: receiver(8898) hub($HUB_PORT) node-a node-b"
    ;;

  stop)
    for c in cogtrap-node-a cogtrap-node-b cogtrap-hub cogtrap-receiver; do
      "$RUNTIME" stop -t 5 "$c" 2>/dev/null || true
    done
    echo "栈已停止"
    ;;

  status)
    "$RUNTIME" ps -a --filter name=cogtrap --format '{{.Names}}\t{{.Status}}' | sed 's/^/  /'
    ;;

  node)  # 前台跑单节点(调试用): run-stack.sh node node-a
    cmd_node "${2%%-*}" "$2"
    ;;

  *)
    sed -n '2,14p' "$0"; exit 2 ;;
esac
