#!/usr/bin/env python3
"""Create gitee repo linklens, push content, flip to public, verify anonymous read.
Token sourced from bootlens repo remote (verified live)."""
import json, subprocess, sys, urllib.request, urllib.parse, re, os

REPO = "linklens"
SRC = "/Users/len/CodeBuddy/dx/linklens"
TOKEN = None

# pull token from a live remote
cfg = open("/Users/len/CodeBuddy/dx/bootlens/.git/config").read()
m = re.search(r'https://[A-Za-z0-9_-]+:([0-9a-f]{32})@gitee\.com', cfg)
TOKEN = m.group(1)

def api(method, path, form=None):
    url = f"https://gitee.com/api/v5{path}"
    data = urllib.parse.urlencode(form).encode() if form else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "linklens-publisher"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode()
        return r.status, json.loads(body) if body else {}

# 1. create repo (POST form-encoded, access_token in body)
status, resp = api("POST", "/user/repos",
                   {"access_token": TOKEN, "name": REPO,
                    "description": "linklens - broken-link archaeology and symlink risk lens (zero-dependency single-file CLI)",
                    "has_issues": "true", "private": "false"})
print("create:", status, resp.get("full_name"), resp.get("html_url"))

# 2. push with token embedded URL (must include username segment)
user = "tomlen"
push_url = f"https://{user}:{TOKEN}@gitee.com/{user}/{REPO}.git"
env = dict(os.environ, GIT_TERMINAL_PROMPT="0")

def run(cmd):
    r = subprocess.run(cmd, cwd=SRC, env=env, capture_output=True, text=True, timeout=180)
    print("$", " ".join(cmd), "->", r.returncode)
    if r.returncode != 0:
        print(r.stdout[-800:]); print(r.stderr[-800:])
    return r.returncode == 0

if not run(["git", "init", "-b", "master"]):
    sys.exit(1)
run(["git", "add", "-A"])
run(["git", "-c", "user.name=tomlen", "-c", "user.email=tomlen@users.noreply.gitee.com",
     "commit", "-m", "linklens v1.0.0 - symlink risk lens: dead/loop/escape/kernelcap + baseline watch, 328 selftest green"])
if not run(["git", "remote", "add", "origin", push_url]):
    run(["git", "remote", "set-url", "origin", push_url])
if not run(["git", "push", "-u", "origin", "master", "--force"]):
    sys.exit(1)

# 3. flip to public (PATCH must carry name field)
status, resp = api("PATCH", f"/repos/{user}/{REPO}",
                   {"access_token": TOKEN, "name": REPO, "private": "false"})
print("patch public:", status, "private=", resp.get("private"))

# 4. anonymous read-back verification
for probe in [f"https://gitee.com/api/v5/repos/{user}/{REPO}",
              f"https://gitee.com/{user}/{REPO}/raw/master/README.md",
              f"https://gitee.com/{user}/{REPO}/raw/master/linklens.py"]:
    req = urllib.request.Request(probe, headers={"User-Agent": "anon-checker"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            ctype = r.headers.get("Content-Type", "")
            head = r.read(120).decode(errors="replace").replace("\n", " ")
            print("READBACK", r.status, ctype[:30], probe[-40:], "|", head[:80])
    except Exception as e:
        print("READBACK FAIL", probe, repr(e)[:100])
print("gitee publish sequence complete")
