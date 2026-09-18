#!/usr/bin/env bash
# 无浏览器环境下的仪表盘渲染与自检。
#
# 为什么需要这个脚本
# ------------------
# 仪表盘是客户端 fetch 渲染的, 因此"看截图"必须满足两个条件, 否则截出来的
# 是误导性的图:
#   1. **必须等待 JS 取数完成** —— chromium 的 --virtual-time-budget 让定时器
#      与网络在虚拟时间内推进, 否则截到的是"加载中"状态
#   2. **必须截全页** —— --screenshot 只截窗口大小, 窗口不够高会把会话表、
#      战役归因、页脚全切掉。本案实测页面高 2470px, 用 2000px 窗口就漏掉了
#      约 500px 内容
#
# 因此本脚本先按超大窗口渲染, 再用像素分析测出内容实际底部并裁到精确高度,
# 最后打印自检结果(是否可能被截断、底部空白是否合理)。
#
# 依赖:
#   chromium-browser    dnf install -y chromium
#   CJK 字体            dnf install -y wqy-microhei-fonts
#                       **不可省略**: 缺中文字体时整页中文会渲染成空心方框(tofu),
#                       截图不可用, 而且这正暴露了精简 Linux 主机上的真实部署风险。
#
# 用法:
#   bash tools/render_dashboard.sh                      # 默认渲染 127.0.0.1:8899
#   bash tools/render_dashboard.sh http://host:8899 /tmp/out

set -uo pipefail

URL="${1:-http://127.0.0.1:8899/}"
OUT_DIR="${2:-/tmp/cogtrap-render}"
CHROME="$(command -v chromium-browser || command -v chromium || true)"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'
ok()   { echo "${GREEN}  ✓${NC} $*"; }
bad()  { echo "${RED}  ✗${NC} $*"; }
warn() { echo "${YELLOW}  !${NC} $*"; }
info() { echo "${DIM}    $*${NC}"; }

echo "=============================================================="
echo " CogTrap 仪表盘渲染自检"
echo "=============================================================="

# ---------- 前置检查 ----------
if [ -z "$CHROME" ]; then
  bad "未找到 chromium。安装: dnf install -y chromium"
  exit 1
fi
ok "渲染器: $CHROME"

if ! fc-list 2>/dev/null | grep -qiE "cjk|wqy|microhei|noto sans sc"; then
  warn "未检测到中文字体 —— 整页中文会渲染成空心方框(tofu), 截图不可用"
  info "安装: dnf install -y wqy-microhei-fonts"
  info "（这同时说明: 精简 Linux 主机上从缺少中文字体的终端查看本界面会不可读）"
else
  ok "中文字体已就位: $(fc-match 'sans-serif:lang=zh-cn' 2>/dev/null | head -1)"
fi

if ! curl -sS -o /dev/null --max-time 5 "$URL"; then
  bad "仪表盘不可达: $URL"
  info "先启动: cogtrap serve（仪表盘默认监听 127.0.0.1:8899）"
  exit 1
fi
ok "仪表盘可达: $URL"

mkdir -p "$OUT_DIR"

# ---------- 渲染 ----------
render() {
  local name="$1" width="$2" height="$3"
  timeout 180 "$CHROME" --headless --no-sandbox --disable-gpu \
    --disable-dev-shm-usage --hide-scrollbars --force-device-scale-factor=1 \
    --virtual-time-budget=12000 --window-size="$width,$height" \
    --screenshot="$OUT_DIR/raw-$name.png" "$URL" 2>&1 | grep -i "written" >/dev/null
}

echo
echo " 渲染中(等待 JS 取数完成)..."
render desktop 1600 4000
render narrow  700  6000
ok "已渲染 raw-desktop.png / raw-narrow.png"

# ---------- 裁到内容高度 ----------
echo
echo " 测量内容底部并裁剪..."
python3 - "$OUT_DIR" <<'PY'
import struct, sys, zlib, os

out_dir = sys.argv[1]

def load(path):
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "不是 PNG"
    pos, idat = 8, b""
    width = height = colortype = 0
    while pos < len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8]
        chunk = data[pos+8:pos+8+length]
        if ctype == b"IHDR":
            width, height, _depth, colortype = struct.unpack(">IIBB", chunk[:10])
        elif ctype == b"IDAT":
            idat += chunk
        elif ctype == b"IEND":
            break
        pos += 12 + length
    raw = zlib.decompress(idat)
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colortype]
    stride = width * channels
    rows, prev, p = [], bytearray(stride), 0
    for _ in range(height):
        ftype = raw[p]; p += 1
        line = bytearray(raw[p:p + stride]); p += stride
        if ftype == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        rows.append(bytes(line)); prev = line
    return width, height, channels, rows

def save(path, width, channels, rows):
    height = len(rows)
    raw = b"".join(b"\x00" + row for row in rows)
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 6))
    png += chunk(b"IEND", b"")
    open(path, "wb").write(png)

for name, window_h in (("desktop", 4000), ("narrow", 6000)):
    src = os.path.join(out_dir, "raw-%s.png" % name)
    dst = os.path.join(out_dir, "dashboard-%s.png" % name)
    width, height, channels, rows = load(src)
    stride = width * channels
    bg = rows[0][0:3]
    last = 0
    for y in range(height - 1, -1, -1):
        row = rows[y]
        step = max(1, width // 120) * channels
        for x in range(0, stride, step):
            if (abs(row[x] - bg[0]) + abs(row[x + 1] - bg[1])
                    + abs(row[x + 2] - bg[2])) > 6:
                last = y
                break
        if last:
            break
    trailing = height - 1 - last
    keep = min(last + 16, height)
    save(dst, width, channels, rows[:keep])
    print("    %-10s 窗口 %dx%d -> 内容底 %d -> 输出 %dx%d (底部留白 %d)"
          % (name, width, window_h, last, width, keep, 15))
    if last >= window_h - 20:
        print("    \033[33m! 内容触到窗口下缘, 可能被截断 —— 请加大窗口高度重渲染\033[0m")
PY

echo
echo "=============================================================="
ok "渲染完成: $OUT_DIR/dashboard-desktop.png 与 dashboard-narrow.png"
info "请人工或交给视觉评审确认观感 —— 自动化只能保证"
info "「等到了数据」「截全了页」「中文字形正常」这三件事。"
echo "=============================================================="
