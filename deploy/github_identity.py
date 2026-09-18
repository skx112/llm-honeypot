#!/usr/bin/env python3
"""推导并配置 GitHub 提交身份 (name/email)。

为什么需要这个工具: GitHub 的 noreply 邮箱在设置页里有时不容易找到
(需要开启"保持我的电子邮件地址私密"才会显示)。而 noreply 地址的格式是
确定的:

    <数字用户ID>+<用户名>@users.noreply.github.com

数字 ID 可以从 api.github.com 查到, 所以这个地址可以直接推导出来, 不必去
UI 里翻。本机 api.github.com 可达, 因此这个工具在当前网络环境下可用。

用法:
    python3 deploy/github_identity.py <用户名>                 # 只查询并打印
    python3 deploy/github_identity.py <用户名> --set           # 查询并写入 git 配置
    python3 deploy/github_identity.py <用户名> --name "张三" --set
    python3 deploy/github_identity.py --verify someone@example.com   # 校验邮箱是否属于某个账户

只用标准库; 无第三方依赖。
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com/users/%s"
TIMEOUT = 15


def fetch_user(username):
    """查询用户基本信息。返回 dict 或抛出 RuntimeError。"""
    request = urllib.request.Request(
        API % username,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "llm-honeypot-identity-tool/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError("用户不存在: %s" % username)
        if exc.code == 403:
            raise RuntimeError(
                "API 速率受限(未认证请求每小时 60 次), 请稍后重试或提供令牌")
        raise RuntimeError("API 返回 HTTP %d" % exc.code)
    except urllib.error.URLError as exc:
        raise RuntimeError("无法访问 api.github.com: %s" % exc.reason)
    except (ValueError, OSError) as exc:
        raise RuntimeError("响应解析失败: %s" % exc)


def noreply_for(user):
    """构造现代格式的 noreply 邮箱。"""
    return "%s+%s@users.noreply.github.com" % (user["id"], user["login"])


def legacy_noreply_for(user):
    """老账户的旧格式, GitHub 同样识别(无数字前缀)。"""
    return "%s@users.noreply.github.com" % user["login"]


def git_config(key):
    try:
        out = subprocess.check_output(["git", "config", "--global", key],
                                      stderr=subprocess.DEVNULL)
        return out.decode("utf-8", "replace").strip()
    except (subprocess.CalledProcessError, OSError):
        return ""


def set_git_config(key, value):
    try:
        subprocess.check_call(["git", "config", "--global", key, value],
                              stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, OSError) as exc:
        print("  设置 %s 失败: %s" % (key, exc), file=sys.stderr)
        return False


def cmd_lookup(args):
    user = fetch_user(args.username)
    print("=" * 62)
    print(" GitHub 账户信息")
    print("=" * 62)
    print("  用户名      : %s" % user.get("login"))
    print("  显示名      : %s" % (user.get("name") or "(未设置)"))
    print("  数字 ID     : %s" % user.get("id"))
    print("  公开邮箱    : %s" % (user.get("email") or "(未公开, 正常)"))
    print("  账户类型    : %s" % user.get("type"))
    print()
    print("  推荐提交邮箱(现代格式 noreply, 保护真实邮箱):")
    print("    %s" % noreply_for(user))
    print()
    print("  旧格式 noreply(老账户兼容, 同样可用):")
    print("    %s" % legacy_noreply_for(user))
    print()
    print("  真实邮箱(如果你不介意公开, 且该邮箱已验证绑定到账户):")
    print("    %s" % (user.get("email") or "该用户未公开邮箱, 请用你自己知道的那个"))
    print()

    print("=" * 62)
    print(" 当前本机 git 配置")
    print("=" * 62)
    current_name = git_config("user.name")
    current_email = git_config("user.email")
    print("  user.name   : %s" % (current_name or "(未设置)"))
    print("  user.email  : %s" % (current_email or "(未设置)"))
    print()

    if args.set:
        name = args.name or user.get("name") or user.get("login")
        email = args.email or noreply_for(user)
        print("=" * 62)
        print(" 写入 git 全局配置")
        print("=" * 62)
        if set_git_config("user.name", name):
            print("  ✓ user.name  = %s" % name)
        if set_git_config("user.email", email):
            print("  ✓ user.email = %s" % email)
        print()
        print("  提交署名将显示为: %s <%s>" % (name, email))
        print("  该地址会被 GitHub 识别并归属到 %s 账户。" % user.get("login"))
    else:
        print("  提示: 加 --set 参数即可自动写入上面的推荐值")
    return 0


def cmd_verify(args):
    """校验一个邮箱地址是否属于某个 GitHub 账户(即提交能否正确归属)。"""
    email = args.verify
    print("校验邮箱: %s" % email)
    local_part = email.split("@")[0]
    domain = email.split("@")[-1].lower()

    ok = False
    if domain == "users.noreply.github.com":
        if "+" in local_part:
            user_id, _, login = local_part.partition("+")
            print("  形式: 现代 noreply (含数字 ID)")
            try:
                user = fetch_user(login)
            except RuntimeError as exc:
                print("  查询失败: %s" % exc)
                return 2
            if str(user["id"]) == user_id:
                print("  ✓ 数字 ID 与账户 %s 匹配, 提交会正确归属" % user["login"])
                ok = True
            else:
                print("  ✗ 数字 ID 不匹配!")
                print("    你填的是 %s, 但 %s 的实际 ID 是 %s" % (user_id, login, user["id"]))
                print("    正确写法: %s" % noreply_for(user))
        else:
            print("  形式: 旧格式 noreply")
            try:
                user = fetch_user(local_part)
            except RuntimeError as exc:
                print("  查询失败: %s" % exc)
                return 2
            print("  ✓ 账户 %s 存在, 旧格式 noreply 可用" % user["login"])
            ok = True
    else:
        print("  形式: 普通邮箱")
        print("  无法通过公开 API 校验它是否绑定到你的账户(GitHub 不公开账户邮箱列表)。")
        print("  请自行确认该邮箱已在此页面验证: https://github.com/settings/emails")
        print("  未绑定到账户的邮箱会导致提交显示为'未归属', 但仍能推送成功。")

    if not ok and domain == "users.noreply.github.com":
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="推导并配置 GitHub 提交身份",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("username", nargs="?", help="GitHub 用户名")
    parser.add_argument("--set", action="store_true", help="把结果写入 git 全局配置")
    parser.add_argument("--name", help="提交署名用的显示名(默认用账户显示名或用户名)")
    parser.add_argument("--email", help="直接指定提交邮箱(默认用推导出的 noreply)")
    parser.add_argument("--verify", metavar="EMAIL", help="校验某个邮箱能否正确归属")
    args = parser.parse_args(argv)

    if args.verify:
        return cmd_verify(args)
    if not args.username:
        parser.print_help()
        return 2
    try:
        return cmd_lookup(args)
    except RuntimeError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
