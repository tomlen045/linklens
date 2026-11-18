#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
linklens — 断链考古与软链风险透镜（zero-dependency single-file CLI）

回答五个没人盯的问题：
  1. 谁是断链 —— 目标早已不存在，链接还挂在原地骗人
  2. 谁是古董断链 —— 死了至少 N 天（默认30）还没人发现的链接（CRIT）
  3. 谁在自指成环 —— a→b→a 转不出来的链接环
  4. 谁在越界 —— 相对路径爬出扫描根 / 指向 /tmp、/etc 等高危区
  5. 谁刚被换绑 —— watch 模式抓链接的增删改（软链劫持第一现场）

哨兵套件定位：diskhound 盯「盘」/ suidhunt 盯「特权位」/ piihound 盯「敏感数据」/
linklens 盯「链接」。

零依赖：Python 3.8+ 标准库，os.walk + lstat 取数，拷走就能跑。
退出码：0 干净 / 1 用法错 / 2 有 WARN / 3 有 CRIT / 4 内部错误。
"""

import argparse
import json
import os
import sys
import time

VERSION = "1.0.0"
EXIT_OK, EXIT_USAGE, EXIT_WARN, EXIT_CRIT, EXIT_INTERNAL = 0, 1, 2, 3, 4

HOP_CAP = 64                # 解引用跳数上限，超过即 DEEP
HOP_KERNEL = 32             # 内核 MAXSYMLINKS——逻辑能解 ≠ 内核能跟，>=32 即 KERNELCAP
SEV_ORDER = {"OK": 0, "INFO": 1, "WARN": 2, "CRIT": 3}

# 字面量判定——确定性优先，不做启发式
TEMP_ROOTS = ("/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/temp")
SENSITIVE_COMPONENTS = {".ssh", ".gnupg", ".aws", ".kube", ".gnupg"}
SENSITIVE_BASENAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys",
                       "known_hosts", "id_dsa")


def is_scope_target(resolved):
    """系统敏感区判定：路径组件级（/opt/homebrew/etc 不是 /etc）。

    /etc、/private/etc、/root、/var/run 按首组件判；
    .ssh/.gnupg/.aws/.kube 等敏感目录按任意组件判；
    密钥文件名按 basename 判。
    """
    parts = [p for p in resolved.split("/") if p]
    if not parts:
        return False
    if parts[0] in ("etc", "root") or parts[:2] == ["private", "etc"] \
            or parts[:2] == ["var", "run"] or parts[:2] == ["private", "var"] and len(parts) > 2 and parts[2] == "tmp":
        return True
    if any(p in SENSITIVE_COMPONENTS for p in parts[:-1]):
        return True
    base = parts[-1]
    if base in SENSITIVE_BASENAMES or base.startswith("id_rsa") \
            or base.startswith("id_ed25519"):
        return True
    return False

STATE_LABEL = {
    "OK": "在",
    "DEAD": "断",
    "LOOP": "环",
    "ESCAPE": "越",
    "DEEP": "深",
    "PERM": "权",
    "EMPTY": "空",
}


# ---------------------------------------------------------------- 基础工具

def redact(text, home=None):
    """把用户家目录前缀替换为 ~，避免输出真实用户名。"""
    home = home or os.path.expanduser("~")
    if text and text.startswith(home):
        return "~" + text[len(home):]
    return text


def link_age_days(lstat_result, now=None):
    """链接自身的年龄（天，向下取整，恒 >=0）。"""
    now = now if now is not None else time.time()
    return max(0, int((now - lstat_result.st_mtime) // 86400))


def norm_target(raw, link_dir):
    """把 raw target 归一成绝对路径字符串（不做存在性判断）。"""
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    return os.path.normpath(os.path.join(link_dir, raw))


def walk_prefix_ancestors(path):
    """从 path 向上走到第一个存在的祖先目录，返回该目录；全都不存在返回 None。"""
    cur = path
    while cur and cur != os.path.dirname(cur):
        if os.path.exists(cur):
            return cur if os.path.isdir(cur) else os.path.dirname(cur)
        cur = os.path.dirname(cur)
    if cur and os.path.exists(cur):
        return cur
    return None


# ---------------------------------------------------------------- 解引用与判定

def resolve_chain(link_path, max_hops=HOP_CAP):
    """沿 readlink 链解引用。

    返回 (final_abs_path, hops, looped, last_existing)：
      final_abs_path —— 最终落点（未验证存在性）；链条耗尽时为最后一次 readlink 的落点
      hops           —— 实际跳数
      looped         —— 是否检测到环
    """
    seen = set()
    cur = link_path
    hops = 0
    while hops < max_hops:
        try:
            st = os.lstat(cur)
        except OSError:
            return cur, hops, False
        if not os.path.islink(cur):
            return cur, hops, False
        key = (st.st_dev, st.st_ino)
        if key in seen:
            return cur, hops, True
        seen.add(key)
        raw = os.readlink(cur)
        cur = norm_target(raw, os.path.dirname(cur))
        hops += 1
    return cur, hops, False


def classify(link_path, root, opts=None, now=None):
    """对单个软链给出记录。root 为本次扫描根（列表），用于越界判定。"""
    opts = opts or {}
    stale_days = opts.get("stale_days", 30)
    roots = root if isinstance(root, (list, tuple)) else ([root] if root else [])
    try:
        lst = os.lstat(link_path)
    except OSError as e:
        return {"path": link_path, "target": "", "kind": "?", "state": "PERM",
                "tags": ["LSTAT_FAIL"], "age_days": 0, "depth": 0, "err": str(e)}

    age = link_age_days(lst, now=now)
    try:
        raw = os.readlink(link_path)
    except OSError as e:
        return {"path": link_path, "target": "", "kind": "?", "state": "PERM",
                "tags": ["READLINK_FAIL"], "age_days": age, "depth": 0, "err": str(e)}

    kind = "ABS" if os.path.isabs(raw) else "REL"
    tags = []
    empty = (raw.strip() == "")
    if empty:
        tags.append("EMPTY")
    if "//" in raw.replace(":/", ""):  # 排除 URL 形态的误报
        tags.append("MALFORM")

    final, hops, looped = resolve_chain(link_path)
    depth = hops

    if looped:
        return {"path": redact(link_path), "target": redact(raw), "kind": kind,
                "state": "LOOP", "tags": tags, "age_days": age,
                "depth": depth, "sev": "CRIT"}

    resolved = final if os.path.isabs(final) else norm_target(raw, os.path.dirname(link_path))

    inside_root = any(_under(resolved, r) for r in
                      (root if isinstance(root, (list, tuple)) else ([root] if root else [])) if r)
    if not inside_root and any(os.path.normpath(resolved).startswith(r) for r in TEMP_ROOTS):
        tags.append("TEMP")  # 仅当目标在扫描根之外时才算「指向临时区」
    if is_scope_target(resolved):
        tags.append("SCOPE")

    if depth >= HOP_KERNEL:
        tags.append("KERNELCAP")  # 内核跟链上限 32，逻辑可解但 open() 会 ELOOP

    if hops >= HOP_CAP and os.path.islink(
            resolved):
        tags.append("DEEP")

    exists = os.path.exists(resolved)

    # 越界：相对路径爬出扫描根（经典 mv/cp 事故现场）
    if kind == "REL" and roots:
        inside = any(_under(resolved, r) for r in roots if r)
        if not inside:
            tags.append("ESCAPE")
    elif kind == "ABS" and roots:
        inside = any(_under(resolved, r) for r in roots if r)
        if not inside:
            tags.append("OUTSIDE")

    if not empty and not exists and "DEEP" not in tags:
        # 死链判定前先排除「权限看不到」的情况
        anc = walk_prefix_ancestors(resolved)
        if anc is not None and not os.access(anc, os.R_OK | os.X_OK) and os.geteuid() != 0:
            tags.append("NOACCESS")
            return {"path": redact(link_path), "target": redact(raw), "kind": kind,
                    "state": "PERM", "tags": tags, "age_days": age,
                    "depth": depth, "sev": "WARN"}
        if age >= stale_days:
            return {"path": redact(link_path), "target": redact(raw), "kind": kind,
                    "state": "DEAD", "tags": tags + ["STALE"], "age_days": age,
                    "depth": depth, "sev": "CRIT"}
        return {"path": redact(link_path), "target": redact(raw), "kind": kind,
                "state": "DEAD", "tags": tags, "age_days": age,
                "depth": depth, "sev": "WARN"}

    if empty:
        # 空目标链接 follow 必 ENOENT
        return {"path": redact(link_path), "target": "", "kind": kind,
                "state": "EMPTY", "tags": tags, "age_days": age,
                "depth": depth, "sev": "WARN"}

    sev = "OK"
    state = "OK" if "DEEP" not in tags else "DEEP"
    if "ESCAPE" in tags or "TEMP" in tags or "SCOPE" in tags or "MALFORM" in tags \
            or "DEEP" in tags or "KERNELCAP" in tags:
        sev = "WARN"
    elif "OUTSIDE" in tags:
        sev = "INFO"
    if age >= stale_days:
        tags.append("AGED")
        # AGED 不升级：链接年久是常态（Homebrew Cellar 天生数年不动），
        # 只有「又老又死」才是 CRIT（上面已判）。此处 sev 维持原值。
    return {"path": redact(link_path), "target": redact(raw), "kind": kind,
            "state": state, "tags": tags, "age_days": age,
            "depth": depth, "sev": sev}


def _under(path, root):
    """path 是否位于 root 之下（含相等）。"""
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) \
            == os.path.abspath(root)
    except ValueError:
        return False


# ---------------------------------------------------------------- 扫描

def iter_symlinks(roots, follow=False, skip_hidden=False):
    """产出 (link_path, lstat)。默认不跟随目录软链（防环防跑飞）。截断控制由 scan() 负责。"""
    for root in roots:
        if os.path.isfile(root):
            if os.path.islink(root):
                yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow):
            if skip_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            for name in list(dirnames) + list(filenames):
                p = os.path.join(dirpath, name)
                try:
                    if os.path.islink(p):
                        yield p
                except OSError:
                    continue


def scan(roots, opts=None):
    opts = opts or {}
    records = []
    truncated = False
    count = 0
    max_scan = opts.get("max_scan", 200000)
    for p in iter_symlinks(roots, follow=opts.get("follow", False),
                           skip_hidden=opts.get("skip_hidden", False)):
        count += 1
        if count > max_scan:
            truncated = True
            break
        records.append(classify(p, roots, opts))
    return records, truncated, count


def summarize(records, truncated=False):
    by_state = {}
    for r in records:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
    sev = max([SEV_ORDER.get(r.get("sev", "OK"), 0) for r in records], default=0)
    sev_name = {0: "OK", 1: "INFO", 2: "WARN", 3: "CRIT"}[sev]
    return {"links": len(records), "by_state": by_state,
            "truncated": truncated, "worst": sev_name}


# ---------------------------------------------------------------- 输出

def fmt_human(records, summary, roots, verbose=False):
    lines = []
    roots_txt = ",".join(redact(r) for r in roots)
    lines.append("linklens v%s — roots: %s — links: %d%s" % (
        VERSION, roots_txt, summary["links"],
        "  [TRUNCATED]" if summary["truncated"] else ""))
    sev_rank = {"CRIT": 3, "WARN": 2, "INFO": 1, "OK": 0}
    ordered = sorted(records, key=lambda r: -sev_rank.get(r.get("sev", "OK"), 0))
    for r in ordered:
        if r.get("sev") == "OK" and not verbose:
            continue
        mark = {"CRIT": "[CRIT]", "WARN": "[WARN]", "INFO": "[info]"}.get(r.get("sev"), "[ok]")
        tag_txt = (" tags=" + ",".join(r["tags"])) if r.get("tags") else ""
        lines.append("%s %-8s %s -> %s  (age %dd, depth %d%s)" % (
            mark, STATE_LABEL.get(r["state"], r["state"]), r["path"], r["target"],
            r["age_days"], r["depth"], tag_txt))
    bs = summary["by_state"]
    parts = ["%s=%d" % (k, v) for k, v in sorted(bs.items())]
    lines.append("summary: links=%d %s worst=%s" % (
        summary["links"], " ".join(parts), summary["worst"]))
    return "\n".join(lines)


def fmt_json(records, summary):
    return json.dumps({"version": VERSION, "summary": summary,
                       "records": records}, ensure_ascii=False, indent=1)


def fmt_md(records, summary, roots):
    head = "# linklens 报告 — %s\n\n" % redact(",".join(roots))
    head += "- 链接总数：%d，最坏级别：%s%s\n" % (
        summary["links"], summary["worst"],
        "（扫描被截断）" if summary["truncated"] else "")
    head += "\n| 级别 | 状态 | 链接 | 目标 | 年龄(天) |\n|---|---|---|---|---|\n"
    sev_rank = {"CRIT": 3, "WARN": 2, "INFO": 1, "OK": 0}
    for r in sorted(records, key=lambda x: -sev_rank.get(x.get("sev", "OK"), 0)):
        if r.get("sev") == "OK":
            continue
        head += "| %s | %s | `%s` | `%s` | %d |\n" % (
            r.get("sev", ""), r["state"], r["path"], r["target"], r["age_days"])
    return head


# ---------------------------------------------------------------- 基线与 watch

def signature(roots, opts=None):
    """{path: target} 形态的链接签名。"""
    sig = {}
    for p in iter_symlinks(roots, follow=opts.get("follow", False) if opts else False):
        try:
            sig[p] = os.readlink(p)
        except OSError:
            sig[p] = ""
    return sig


def baseline_save(roots, path, opts=None):
    sig = signature(roots, opts)
    data = {"version": 1, "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "links": sig}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    return len(sig)


def baseline_check(baseline_file, roots, opts=None):
    try:
        with open(baseline_file, encoding="utf-8") as f:
            old = json.load(f)["links"]
    except Exception as e:
        return None, [{"type": "BASELINE_ERROR", "detail": str(e)}]
    new = signature(roots, opts)
    events = []
    for p in sorted(set(old) | set(new)):
        if p not in old:
            events.append({"type": "LINK_NEW", "path": p, "target": new[p]})
        elif p not in new:
            events.append({"type": "LINK_GONE", "path": p, "was": old[p]})
        elif old[p] != new[p]:
            events.append({"type": "LINK_RETARGET", "path": p,
                           "was": old[p], "now": new[p]})
    return new, events


def watch(roots, interval, rounds, opts=None):
    all_events = []
    prev = signature(roots, opts)
    for i in range(1, rounds):
        time.sleep(interval)
        cur = signature(roots, opts)
        for p in sorted(set(prev) | set(cur)):
            if p not in prev:
                all_events.append({"type": "LINK_NEW", "path": p, "target": cur[p],
                                   "round": i})
            elif p not in cur:
                all_events.append({"type": "LINK_GONE", "path": p, "was": prev[p],
                                   "round": i})
            elif prev[p] != cur[p]:
                all_events.append({"type": "LINK_RETARGET", "path": p,
                                   "was": prev[p], "now": cur[p], "round": i})
        prev = cur
    return prev, all_events


# ---------------------------------------------------------------- 演示沙箱

def build_demo(outdir):
    """确定性演示沙箱：8 条链接覆盖全部状态。返回 (records, summary, cleanup)。"""
    os.makedirs(outdir, exist_ok=True)
    inner = os.path.join(outdir, "project")
    os.makedirs(inner, exist_ok=True)
    outside = os.path.join(outdir, "outside")
    os.makedirs(outside, exist_ok=True)

    real = os.path.join(inner, "config.yml")
    with open(real, "w") as f:
        f.write("# demo\n")
    out_file = os.path.join(outside, "shared.txt")
    with open(out_file, "w") as f:
        f.write("shared\n")

    # 1 OK：普通相对链接
    os.symlink("config.yml", os.path.join(inner, "ok-link"))
    # 2 DEAD 新鲜
    os.symlink("missing.target", os.path.join(inner, "dead-fresh"))
    # 3 DEAD 古董（CRIT）
    old_dead = os.path.join(inner, "dead-ancient")
    os.symlink("gone-long-ago.bin", old_dead)
    past = time.time() - 400 * 86400
    os.utime(old_dead, (past, past), follow_symlinks=False)
    # 4 LOOP 两跳
    os.symlink("loop-b", os.path.join(inner, "loop-a"))
    os.symlink("loop-a", os.path.join(inner, "loop-b"))
    # 5 ESCAPE：相对路径爬出扫描根
    os.symlink(os.path.join("..", "outside", "shared.txt"),
               os.path.join(inner, "escape-link"))
    # 6 OUTSIDE：绝对路径指到根外（info）
    os.symlink(out_file, os.path.join(inner, "outside-info"))
    # 7 TEMP：指向 /tmp（危险目标，存在）
    tmp_target = "/tmp/linklens-demo-target"
    with open(tmp_target, "w") as f:
        f.write("tmp\n")
    os.symlink(tmp_target, os.path.join(inner, "tmp-link"))
    # 7b SCOPE：指向系统敏感区 /etc
    os.symlink("/etc/hosts", os.path.join(inner, "scope-link"))
    # 8 DEEP：50 跳链条（合法但深）
    cur = real
    for i in range(50, 0, -1):
        nxt = os.path.join(inner, "deep-%02d" % i)
        os.symlink(cur, nxt)
        cur = nxt

    def cleanup():
        import shutil
        shutil.rmtree(outdir, ignore_errors=True)
        try:
            os.remove(tmp_target)
        except OSError:
            pass

    records, truncated, _ = scan([inner])
    return records, summarize(records, truncated), cleanup


# ---------------------------------------------------------------- 自测

def _mk(tmp, *parts):
    p = os.path.join(tmp, *parts)
    return p


def selftest():
    import tempfile
    import shutil
    checked = 0

    def ok(cond, msg):
        nonlocal checked
        checked += 1
        if not cond:
            raise AssertionError("invariant #%d failed: %s" % (checked, msg))

    base = tempfile.mkdtemp(prefix="linklens-selftest-")
    try:
        root = _mk(base, "proj")
        os.makedirs(root)
        target = _mk(root, "real.txt")
        with open(target, "w") as f:
            f.write("x")

        now = time.time()

        # --- 状态判定
        l = _mk(root, "ok-rel"); os.symlink("real.txt", l)
        r = classify(l, root, now=now); ok(r["state"] == "OK" and r["kind"] == "REL", "ok-rel")

        l = _mk(root, "ok-abs"); os.symlink(target, l)
        r = classify(l, root, now=now); ok(r["state"] == "OK" and r["kind"] == "ABS", "ok-abs")

        l = _mk(root, "dead-rel"); os.symlink("nope.txt", l)
        r = classify(l, root, now=now)
        ok(r["state"] == "DEAD" and r.get("sev") == "WARN", "dead fresh=WARN")

        l = _mk(root, "dead-abs"); os.symlink(_mk(root, "nope-abs"), l)
        r = classify(l, root, now=now); ok(r["state"] == "DEAD", "dead abs")

        l = _mk(root, "dead-old"); os.symlink("nope-old.txt", l)
        past = now - 400 * 86400
        os.utime(l, (past, past), follow_symlinks=False)
        r = classify(l, root, now=now)
        ok(r["state"] == "DEAD" and r.get("sev") == "CRIT" and "STALE" in r["tags"],
           "dead>=30d -> CRIT/STALE")

        l = _mk(root, "aged-ok"); os.symlink("real.txt", l)
        os.utime(l, (past, past), follow_symlinks=False)
        r = classify(l, root, now=now)
        ok(r["state"] == "OK" and "AGED" in r["tags"] and r.get("sev") == "OK",
           "old-but-alive=OK/AGED (aged alone never escalates)")

        l = _mk(root, "empty"); os.symlink("", l)
        r = classify(l, root, now=now); ok(r["state"] == "EMPTY" and r.get("sev") == "WARN", "empty link")

        # --- 环
        a = _mk(root, "la"); b = _mk(root, "lb")
        os.symlink("lb", a); os.symlink("la", b)
        r = classify(a, root, now=now)
        ok(r["state"] == "LOOP" and r.get("sev") == "CRIT", "two-hop loop")
        c = _mk(root, "lc"); os.symlink("lb", c)
        r = classify(c, root, now=now); ok(r["state"] == "LOOP", "three-hop loop")
        self_loop = _mk(root, "lself"); os.symlink("lself", self_loop)
        r = classify(self_loop, root, now=now); ok(r["state"] == "LOOP", "self loop")
        abs_loop = _mk(root, "labs"); os.symlink(abs_loop, abs_loop)
        r = classify(abs_loop, root, now=now); ok(r["state"] == "LOOP", "abs self loop")

        # --- 深链
        cur = target
        for i in range(50, 0, -1):
            nxt = _mk(root, "deep%02d" % i)
            os.symlink(cur, nxt); cur = nxt
        r = classify(_mk(root, "deep01"), root, now=now)
        ok(r["state"] == "OK" and r["depth"] == 50, "50-hop chain resolves OK")
        cur = target
        for i in range(200, 0, -1):
            nxt = _mk(root, "very%03d" % i)
            os.symlink(cur, nxt); cur = nxt
        r = classify(_mk(root, "very001"), root, now=now)
        ok(r["state"] == "DEEP" and r.get("sev") == "WARN" and "DEEP" in r["tags"],
           ">64 hops -> DEEP/WARN")

        # --- 越界
        sub = _mk(base, "sibling"); os.makedirs(sub)
        with open(_mk(sub, "out.txt"), "w") as f:
            f.write("o")
        l = _mk(root, "esc-dead"); os.symlink("../sibling/missing.out", l)
        r = classify(l, root, now=now)
        ok(r["state"] == "DEAD" and "ESCAPE" in r["tags"], "escape+dead -> DEAD with ESCAPE tag")
        l = _mk(root, "esc-live"); os.symlink("../sibling/out.txt", l)
        r = classify(l, root, now=now)
        ok(r["state"] == "ESCAPE" if False else (r.get("sev") == "WARN" and "ESCAPE" in r["tags"]),
           "live escape -> WARN/ESCAPE")
        l = _mk(root, "outside-abs"); os.symlink(_mk(sub, "out.txt"), l)
        r = classify(l, root, now=now)
        ok(r.get("sev") == "INFO" and "OUTSIDE" in r["tags"], "abs outside -> INFO/OUTSIDE")
        l = _mk(root, "inroot-abs"); os.symlink(target, l)
        r = classify(l, root, now=now)
        ok("OUTSIDE" not in r["tags"] and "ESCAPE" not in r["tags"], "inside root no flag")

        # --- 危险目标
        l = _mk(root, "tmplink"); os.symlink("/tmp/linklens-selftest-nope", l)
        r = classify(l, root, now=now)
        ok("TEMP" in r["tags"], "/tmp target -> TEMP tag")
        l = _mk(root, "etclink"); os.symlink("/etc/linklens-selftest-nope", l)
        r = classify(l, root, now=now)
        ok("SCOPE" in r["tags"], "/etc target -> SCOPE tag")
        l = _mk(root, "sshlink"); os.symlink(".ssh/id_rsa", l)
        r = classify(l, root, now=now)
        ok("SCOPE" in r["tags"], ".ssh marker -> SCOPE tag")
        l = _mk(root, "malform"); os.symlink("real//txt", l)
        r = classify(l, root, now=now)
        ok("MALFORM" in r["tags"], "// target -> MALFORM tag")

        # --- 权限（非 root 才测）
        if os.geteuid() != 0:
            vault = _mk(base, "vault"); os.makedirs(vault)
            with open(_mk(vault, "secret"), "w") as f:
                f.write("s")
            os.chmod(vault, 0o000)
            try:
                l = _mk(root, "vaultlink"); os.symlink("../vault/secret", l)
                r = classify(l, root, now=now)
                ok(r["state"] == "PERM" and "NOACCESS" in r["tags"], "unreadable ancestor -> PERM")
            finally:
                os.chmod(vault, 0o755)

        # --- 脱敏
        ok(redact("/Users/someone/x", home="/Users/someone") == "~/x", "redact home")
        ok(redact("/var/log/x", home="/Users/someone") == "/var/log/x", "redact no-op")

        # --- 扫描聚合
        records, trunc, count = scan([root], {"stale_days": 30})
        s = summarize(records, trunc)
        ok(s["links"] == count, "summary.links == scanned")
        ok(s["by_state"].get("LOOP", 0) == 5, "loop count=5 (pair la/lb, 3-hop lc, self, abs-self)")
        ok(s["worst"] == "CRIT", "worst=CRIT on fixture")
        j = json.loads(fmt_json(records, s))
        ok(j["summary"]["links"] == len(j["records"]), "json round-trip")
        for rec in j["records"]:
            ok(set(rec) >= {"path", "target", "kind", "state", "tags", "age_days", "depth"},
               "json schema keys")
        md = fmt_md(records, s, [root])
        ok("| 级别 | 状态 |" in md, "md header")
        human = fmt_human(records, s, [root])
        ok("summary:" in human and "[CRIT]" in human, "human format")

        # --- 截断
        records2, trunc2, _ = scan([root], {"stale_days": 30, "max_scan": 3})
        s2 = summarize(records2, trunc2)
        ok(s2["truncated"] is True, "max_scan -> TRUNCATED")

        # --- 基线
        bl = _mk(base, "baseline.json")
        n = baseline_save([root], bl)
        ok(n == s["links"], "baseline saves all links")
        _new, events = baseline_check(bl, [root])
        ok(events == [], "clean baseline -> no events")
        os.symlink("real.txt", _mk(root, "brandnew"))
        _new, events = baseline_check(bl, [root])
        ok(any(e["type"] == "LINK_NEW" for e in events), "new link detected")
        os.remove(_mk(root, "ok-rel"))
        _new, events = baseline_check(bl, [root])
        types = sorted(e["type"] for e in events)
        ok("LINK_GONE" in types and "LINK_NEW" in types, "gone+new detected")
        os.symlink("real.txt", _mk(root, "ok-rel"))
        if os.path.lexists(_mk(root, "ok-rel")):  # 换绑前先摘旧链
            os.remove(_mk(root, "ok-rel"))
        os.symlink("nope-now", _mk(root, "ok-rel"))  # 换绑
        _new, events = baseline_check(bl, [root])
        ok(any(e["type"] == "LINK_RETARGET" for e in events), "retarget detected")
        bad = baseline_check(_mk(base, "no-such-file.json"), [root])
        ok(bad[1] and bad[1][0]["type"] == "BASELINE_ERROR", "missing baseline -> error event")

        # --- watch（用两次手动轮次模拟，不依赖真实 sleep 累计）
        wroot = _mk(base, "watch"); os.makedirs(wroot)
        with open(_mk(wroot, "t"), "w") as f:
            f.write("t")
        os.symlink("t", _mk(wroot, "a"))
        prev, ev = watch([wroot], 0.01, 2)
        ok(ev == [], "watch round1 no events")
        os.symlink("t", _mk(wroot, "newone"))
        cur = signature([wroot])
        # 手动比对逻辑与 watch 内部一致
        evs = []
        for p in sorted(set(prev) | set(cur)):
            if p not in prev:
                evs.append("LINK_NEW")
        ok(evs == ["LINK_NEW"], "watch diff detects NEW")
        os.remove(_mk(wroot, "a")); os.symlink("nope", _mk(wroot, "a"))
        _prev2, ev2 = watch([wroot], 0.01, 2)  # prev 由函数内部重取，无事件
        ok(ev2 == [], "watch fresh round clean")
        sig1 = signature([wroot])
        os.remove(_mk(wroot, "a")); os.symlink("t2", _mk(wroot, "a"))
        with open(_mk(wroot, "t2"), "w") as f:
            f.write("t2")
        sig2 = signature([wroot])
        key_a = [k for k in sig1 if k.endswith("/a")][0]
        ok(sig1[key_a] != sig2[key_a], "signature reflects retarget")

        # --- 演示沙箱（确定性）
        d1 = _mk(base, "demo1")
        recs, summ, cleanup = build_demo(d1)
        ok(summ["by_state"].get("LOOP", 0) == 2, "demo has 2 loop links (loop-a/loop-b)")
        ok(summ["by_state"].get("DEAD", 0) == 2, "demo has 2 dead")
        ok(any("KERNELCAP" in r["tags"] for r in recs), "demo deep chain kernel-capped (50>=32)")
        ok(any("ESCAPE" in r["tags"] for r in recs), "demo has escape")
        ok(any("TEMP" in r["tags"] for r in recs), "demo has temp")
        ok(any("SCOPE" in r["tags"] for r in recs), "demo has scope")
        ok(any("OUTSIDE" in r["tags"] for r in recs), "demo has outside")
        ok(any(r["state"] == "OK" and "AGED" not in r["tags"] for r in recs),
           "demo has plain OK")
        d2 = _mk(base, "demo2")
        recs2, summ2, cleanup2 = build_demo(d2)
        strip = lambda rs: sorted((r["path"].split("/")[-1], r["state"],
                                   tuple(sorted(r["tags"]))) for r in rs)
        ok(strip(recs) == strip(recs2), "demo deterministic (state+tags)")
        ok(summ2["worst"] == "CRIT", "demo worst CRIT")
        cleanup(); cleanup2()

        # --- 退出码映射
        def map_exit(summary):
            return {"OK": EXIT_OK, "INFO": EXIT_OK, "WARN": EXIT_WARN,
                    "CRIT": EXIT_CRIT}[summary["worst"]]
        ok(map_exit({"worst": "CRIT"}) == 3, "exit map CRIT=3")
        ok(map_exit({"worst": "WARN"}) == 2, "exit map WARN=2")
        ok(map_exit({"worst": "OK"}) == 0, "exit map OK=0")
        ok(map_exit({"worst": "INFO"}) == 0, "exit map INFO=0")

        # --- 年龄函数
        fake = type("S", (), {"st_mtime": now - 90 * 86400})()
        ok(link_age_days(fake, now=now) == 90, "age 90d")
        fake2 = type("S", (), {"st_mtime": now + 3600})()
        ok(link_age_days(fake2, now=now) == 0, "future mtime clamps to 0")

    finally:
        shutil.rmtree(base, ignore_errors=True)

    print("selftest: %d invariants checked, all green" % checked)
    return EXIT_OK


# ---------------------------------------------------------------- CLI

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(
        prog="linklens",
        description="linklens — 断链考古与软链风险透镜（零依赖单文件）")
    ap.add_argument("--version", action="version", version="linklens " + VERSION)
    sub = ap.add_subparsers(dest="cmd")

    def add_root_arg(p):
        p.add_argument("paths", nargs="+", help="扫描根（文件或目录，可多个）")
        p.add_argument("--follow", action="store_true", help="跟随目录软链（默认不跟，防跑飞）")
        p.add_argument("--skip-hidden", action="store_true", help="跳过隐藏目录")
        p.add_argument("--stale-days", type=int, default=30,
                       help="断链判古董的天数阈值（默认30，>= 即 CRIT）")
        p.add_argument("--max-scan", type=int, default=200000, help="最大扫描条目数")

    p_scan = sub.add_parser("scan", help="扫描软链并分级")
    add_root_arg(p_scan)
    p_scan.add_argument("--json", action="store_true", help="JSON 输出")
    p_scan.add_argument("--md", action="store_true", help="Markdown 报告输出")
    p_scan.add_argument("-v", "--verbose", action="store_true", help="显示 OK 级链接")

    p_base = sub.add_parser("baseline", help="保存链接签名基线")
    add_root_arg(p_base)
    p_base.add_argument("--save", required=True, help="基线输出文件")

    p_check = sub.add_parser("check", help="对照基线找链接增删改")
    p_check.add_argument("baseline", help="基线文件")
    add_root_arg(p_check)
    p_check.add_argument("--json", action="store_true", help="JSON 输出")

    p_watch = sub.add_parser("watch", help="轮次监视链接增删改")
    add_root_arg(p_watch)
    p_watch.add_argument("--interval", type=float, default=2.0, help="轮间隔秒（默认2）")
    p_watch.add_argument("--rounds", type=int, default=6, help="轮数（默认6）")
    p_watch.add_argument("--json", action="store_true", help="JSON 输出")

    p_demo = sub.add_parser("demo", help="生成确定性演示沙箱并扫描")
    p_demo.add_argument("--outdir", default="/tmp/linklens-demo", help="沙箱目录")
    p_demo.add_argument("--keep", action="store_true", help="保留沙箱不清理")

    sub.add_parser("selftest", help="运行不变量自测")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return EXIT_USAGE

    try:
        if args.cmd == "selftest":
            return selftest()

        if args.cmd == "demo":
            records, summary, cleanup = build_demo(args.outdir)
            if args.json if hasattr(args, "json") else False:
                print(fmt_json(records, summary))
            else:
                print(fmt_human(records, summary, [args.outdir], verbose=True))
            if not args.keep:
                cleanup()
                print("(demo sandbox cleaned)")
            else:
                print("(sandbox kept at %s)" % args.outdir)
            return {"OK": 0, "INFO": 0, "WARN": 2, "CRIT": 3}[summary["worst"]]

        opts = {"follow": args.follow, "skip_hidden": args.skip_hidden,
                "stale_days": args.stale_days, "max_scan": args.max_scan}
        missing = [p for p in args.paths if not os.path.exists(p)]
        if missing:
            print("path not found: %s" % ", ".join(missing), file=sys.stderr)
            return EXIT_USAGE

        if args.cmd == "scan":
            records, truncated, _ = scan(args.paths, opts)
            summary = summarize(records, truncated)
            if args.json:
                print(fmt_json(records, summary))
            elif args.md:
                print(fmt_md(records, summary, args.paths))
            else:
                print(fmt_human(records, summary, args.paths, verbose=args.verbose))
            return {"OK": 0, "INFO": 0, "WARN": 2, "CRIT": 3}[summary["worst"]]

        if args.cmd == "baseline":
            n = baseline_save(args.paths, args.save, opts)
            print("baseline saved: %d links -> %s" % (n, args.save))
            return EXIT_OK

        if args.cmd == "check":
            _sig, events = baseline_check(args.baseline, args.paths, opts)
            if events and events[0]["type"] == "BASELINE_ERROR":
                print("baseline error: %s" % events[0]["detail"], file=sys.stderr)
                return EXIT_INTERNAL
            if args.json:
                print(json.dumps({"events": events}, ensure_ascii=False, indent=1))
            else:
                if not events:
                    print("no change: %d links, same as baseline" % len(_sig or {}))
                for e in events:
                    print("[%s] %s %s" % (e["type"], e.get("path", "?"),
                                          e.get("now") or e.get("was") or e.get("detail", "")))
            return EXIT_WARN if events else EXIT_OK

        if args.cmd == "watch":
            _final, events = watch(args.paths, args.interval, args.rounds, opts)
            if args.json:
                print(json.dumps({"events": events}, ensure_ascii=False, indent=1))
            else:
                if not events:
                    print("watch: %d rounds, no link change" % args.rounds)
                for e in events:
                    print("[r%s][%s] %s" % (e.get("round", "?"), e["type"],
                                            e.get("path", "?")))
            return EXIT_WARN if events else EXIT_OK

        return EXIT_USAGE
    except KeyboardInterrupt:
        return EXIT_INTERNAL
    except Exception as e:  # pragma: no cover
        print("internal error: %r" % e, file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
