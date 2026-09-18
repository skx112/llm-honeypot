#!/usr/bin/env python3
"""最小 SOC 接收端: 接收 CogTrap webhook 告警并落成 JSON 行。

部署蜜罐时, 把 config.json 的 alert.webhook_url 指向本服务即可拥有一条
告警外发通道; 生产环境替换为真正的 SOC/机器人网关。

    python3 tools/soc_receiver.py --listen 127.0.0.1:8898 --out alerts.jsonl

每行格式:
    {"received_at": <epoch>, "payload": {原始告警 JSON}}
"""

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def build_handler(path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CogTrap-SOC-Receiver/1.0"

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(min(length, 1 << 20))
            try:
                payload = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                payload = {"_raw": body[:2048].decode("utf-8", "replace")}
            record = {"received_at": time.time(), "payload": payload}
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "a") as handle:
                handle.write(json.dumps(record, ensure_ascii=False,
                                        default=str) + "\n")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt, *args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description="CogTrap webhook 接收端(SOC 模拟)")
    parser.add_argument("--listen", default="127.0.0.1:8898", help="host:port")
    parser.add_argument("--out", default="alerts.jsonl", help="JSON 行输出文件")
    args = parser.parse_args()

    host, _, port = args.listen.rpartition(":")
    server = HTTPServer((host or "127.0.0.1", int(port)), build_handler(args.out))
    print("接收端就绪: http://%s:%d -> %s" % (host or "127.0.0.1", int(port), args.out),
          flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
