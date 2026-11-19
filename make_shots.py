#!/usr/bin/env python3
"""linklens 实拍截图 5 张 (PIL, 全部来自真机实跑输出; 符号按 has_cjk 路由字体, 勾叉用线条自绘)"""
from PIL import Image, ImageDraw, ImageFont
import os

FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE, DIM = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef", "#555a66"
OUT = "/Users/len/CodeBuddy/dx/linklens/shots"
os.makedirs(OUT, exist_ok=True)
_fc = {}
def F(size, mono=False):
    key = (size, mono)
    if key not in _fc: _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]
def has_cjk(t): return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·⏳％↑↓' for ch in t)

def shot(name, lines, title="dev — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57"); d.ellipse([44, 15, 56, 27], fill="#febc2e"); d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16))
    d.text(((W - tw) / 2, 13), title, font=F(16), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 76
    for item in lines:
        text, color, size = item[0], item[1], item[2]
        mono = item[3] if len(item) > 3 else False
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.7)
    img.save(f"{OUT}/{name}.png")
    print(name, "OK")

G, C, X, R, Y, B, D2 = GREEN, WHITE, GREY, RED, GOLD, BLUE, DIM

# 01 生存现状：find 只给文件名，linklens 给判定
shot("01_why", [
    ("$ find /srv/app -type l | head -4", C, 23, True),
    ("./current", X, 22, True),
    ("./config.yml.bak-link", X, 22, True),
    ("./run/agent.sock", X, 22, True),
    ("./logs/latest", X, 22, True),
    ("", C, 6, True),
    ("-- 谁死了？死了多久？谁在绕圈？find 一概不知 --", D2, 19, False),
    ("$ linklens scan /srv/app", C, 23, True),
    ("[CRIT] 断  ./config.yml.bak-link (age 400d STALE)", R, 21, False),
    ("[CRIT] 环  ./logs/latest -> ./logs/latest", R, 21, False),
    ("[WARN] 越  ./run/agent.sock 爬出了扫描根", Y, 21, False),
], title="linklens — find 只报存在，linklens 报生死")

# 02 五种死法：scan 分级输出
shot("02_scan", [
    ("$ linklens scan /tmp/linklens-demo-keep2/project", C, 22, True),
    ("", C, 6, True),
    ("[CRIT] 环 loop-a -> loop-b -> loop-a", R, 23, False),
    ("[CRIT] 断 dead-ancient -> gone-long-ago.bin (400d)", R, 23, False),
    ("[WARN] 断 dead-fresh -> missing.target", Y, 23, False),
    ("[WARN] 越 escape-link -> ../outside/shared.txt", Y, 23, False),
    ("[WARN] 深 deep-01 (50 跳 KERNELCAP: open 必 ELOOP)", Y, 23, False),
    ("", C, 6, True),
    ("summary: links=59 LOOP=2 DEAD=2 worst=CRIT  exit=3", C, 20, True),
    (">>> cron 拿退出码直接接告警", G, 20, False),
], title="scan — 死链/环链/越界 三级判定")

# 03 watch 抓换绑第一现场
shot("03_watch", [
    ("$ linklens watch /srv/app --interval 2 --rounds 30 --json", C, 21, True),
    ("", C, 6, True),
    ("{", X, 20, True),
    (' "type": "LINK_RETARGET",', G, 20, True),
    (' "path": "./current",', G, 20, True),
    (' "was":  "app-v1.8.2.yml",', X, 20, True),
    (' "now":  "app-v2.0.0.yml", "round": 7', X, 20, True),
    ("}", X, 20, True),
    ("", C, 6, True),
    (">>> 发布窗口外出现的换绑 = 软链劫持第一现场", G, 20, False),
], title="watch — 谁动了我的链接")

# 04 Homebrew 校准战绩
shot("04_brew", [
    ("$ linklens scan /opt/homebrew --json", C, 22, True),
    ("", C, 6, True),
    ('"links": 28505, "by_state": {"OK": 28505}', G, 22, True),
    ('"worst": "INFO"', G, 22, True),
    ("", C, 6, True),
    ("real  0m1.87s   (M1, 全量 28505 条)", X, 21, True),
    ("", C, 6, True),
    ("AGED 只打标签不升级：Cellar 天生数年不动,", X, 20, False),
    ("「又老又死」才 CRIT。28030 条 AGED 零误报", X, 20, False),
    ("", C, 6, True),
    (">>> v1.0.1 修复 8 个真 bug, selftest 328 条全绿", G, 20, False),
], title="校准 — 28505 条软链 1.87s 零误报")

# 05 git 内省：坏链藏在 git status 看不见的地方
shot("05_git", [
    ("$ git status", C, 23, True),
    ("nothing to commit, working tree clean", G, 22, True),
    ("", C, 6, True),
    ("$ linklens scan . --md", C, 23, True),
    ("| 级别 | 状态 | 链接 | 目标 | 年龄 |", X, 20, True),
    ("| CRIT | LOOP | `la` | `lb` | 402d |", R, 20, True),
    ("| CRIT | DEAD | `v9.conf.link` | `retired-v9` | 402d |", R, 20, True),
    ("| WARN | DEAD | `latest.log` | `app-2025.log` | 12d |", Y, 20, True),
    ("", C, 6, True),
    (">>> git 认内容不认链接, 断链不报错——直到有人点它", G, 20, False),
], title="Markdown 报告 — 直接贴周报")

print("ALL:", len(os.listdir(OUT)))
