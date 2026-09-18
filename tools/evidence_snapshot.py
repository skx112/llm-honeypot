#!/usr/bin/env python3
"""单向证据快照: 把实例遥测快照到攻击者(蜜罐用户)不可写的位置。

对策针对逃逸审计 V9: 被攻破的蜜罐可写自己的遥测卷(功能必需), 因此
本地证据存在被篡改风险。本脚本以 **root** 身份由 cron 周期执行:
SQLite 在线备份(WAL 安全) + 告警尾快照 + SHA-256 清单 —— 清单本身
追加到 root-only 文件, 事后可校验任何历史快照是否被改动。

用法(cron, root):
    python3 tools/evidence_snapshot.py --root /data/cogtrap --out /data/cogtrap/evidence
"""
import argparse, hashlib, json, os, shutil, sqlite3, time


def backup_db(src, dst):
    """逻辑快照(iterdump): WAL 安全, 且 Python 3.6 起全版本可用
    (Connection.backup 是 3.7+, VACUUM INTO 需要 SQLite 3.27+,
     目标机的 3.26 都不满足 —— 实测踩过)。"""
    source = sqlite3.connect("file:%s?mode=ro" % src, uri=True)
    with open(dst, "w") as out:
        for line in source.iterdump():
            out.write(line + "\n")
    source.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/data/cogtrap")
    ap.add_argument("--out", default="/data/cogtrap/evidence")
    ap.add_argument("--keep", type=int, default=240, help="保留最近 N 份快照")
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    day_dir = os.path.join(args.out, stamp)
    os.makedirs(day_dir, exist_ok=True)

    manifest = []
    for node in ("node-a", "node-b"):
        db = os.path.join(args.root, node, "var", "telemetry.db")
        if not os.path.exists(db):
            continue
        dst = os.path.join(day_dir, "%s-telemetry.sql" % node)
        try:
            backup_db(db, dst)
        except sqlite3.Error as exc:
            manifest.append({"file": dst, "error": str(exc)})
            continue
        manifest.append({"file": dst, "sha256": hashlib.sha256(open(dst, "rb").read()).hexdigest()})
        alerts = os.path.join(args.root, node, "logs", "alerts.log")
        if os.path.exists(alerts):
            dst2 = os.path.join(day_dir, "%s-alerts.log" % node)
            shutil.copy2(alerts, dst2)
            manifest.append({"file": dst2, "sha256": hashlib.sha256(open(dst2, "rb").read()).hexdigest()})

    if not manifest:
        return
    chain_file = os.path.join(args.out, "chain.jsonl")
    prev = ""
    if os.path.exists(chain_file):
        with open(chain_file) as fh:
            for line in fh:
                try:
                    prev = json.loads(line).get("chain", prev)
                except ValueError:
                    pass
    entry = {"ts": time.time(), "snapshot": stamp,
             "prev_sha": prev,
             "chain": hashlib.sha256(
                 (prev + json.dumps(manifest, sort_keys=True)).encode()).hexdigest(),
             "files": manifest}
    with open(chain_file, "a") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # 保留窗口外的旧快照删除(哈希链保留全量历史)
    snaps = sorted(d for d in os.listdir(args.out)
                   if os.path.isdir(os.path.join(args.out, d)))
    for old in snaps[:-args.keep]:
        shutil.rmtree(os.path.join(args.out, old), ignore_errors=True)


if __name__ == "__main__":
    main()
