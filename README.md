# linklens — 断链考古与软链风险透镜

`ps` 看进程，`df` 看盘，`ls -l` 看链接——但没人告诉你：**哪个链接的目标十年前就没了？**
**哪个链接绕回了它自己？** 哪个链接昨晚被悄悄换了绑？

linklens 回答五个没人盯的问题：

1. **谁是断链** —— 目标早已不存在，链接还挂在原地骗人（新鲜死=WARN，死了 ≥30 天没人发现=CRIT）
2. **谁在自指成环** —— a→b→a 转不出来的链接环（CRIT）
3. **谁在越界** —— 相对路径爬出扫描根（ESCAPE），或指向 /tmp、/etc 等高危/敏感区（TEMP/SCOPE）
4. **谁被内核判了死刑** —— 50 跳的链条逻辑上解得开，但内核 `MAXSYMLINKS=32`，`open()` 必 ELOOP（KERNELCAP）
5. **谁刚被换绑** —— `watch` 模式抓链接增删改，软链劫持的第一现场

哨兵套件定位：diskhound 盯「盘」/ suidhunt 盯「特权位」/ piihound 盯「敏感数据」/ **linklens 盯「链接」**。

## 为什么不是 `find -type l`

| 能力 | find | linklens |
|---|---|---|
| 找出所有软链 | ✅ | ✅ |
| 判定死链并区分「死了多久」 | ❌ | ✅ STALE 分级 |
| 环链检测（a→b→a） | ❌ | ✅ LOOP |
| 相对路径爬出扫描根检测 | ❌ | ✅ ESCAPE |
| 指向 /tmp、/etc、密钥文件的敏感目标 | ❌ | ✅ TEMP/SCOPE（路径组件级，`/opt/homebrew/etc` 不误伤） |
| 内核跳数上限预警 | ❌ | ✅ KERNELCAP |
| 基线对照找链接换绑 | ❌ | ✅ baseline/check |
| 轮次 watch 抓第一现场 | ❌ | ✅ watch |
| cron 友好退出码 | ❌ | ✅ 0/2/3/4 |
| 报告格式 | - | human/JSON/Markdown 三种 |

## 快速上手

```bash
# 全量扫描 + 分级（退出码 0 干净 / 2 有WARN / 3 有CRIT）
python3 linklens.py scan /srv/deploy /etc/myapp

# 只要 JSON / Markdown 报告
python3 linklens.py scan /srv/deploy --json
python3 linklens.py scan /srv/deploy --md > linklens-report.md

# 连 OK 的也看（全量清单）
python3 linklens.py scan /srv/deploy -v

# 基线：今天存一版
python3 linklens.py baseline --save /var/lib/linklens/base.json /srv/deploy

# 明天对照：谁新增了链接？谁被换绑？（有事件=exit 2，可直接接告警）
python3 linklens.py check /var/lib/linklens/base.json /srv/deploy

# watch：抓链接换绑的第一现场
python3 linklens.py watch /srv/deploy --interval 2 --rounds 30
```

## 状态与分级（全部确定性判定，无启发式）

| 状态 | 含义 | 级别 |
|---|---|---|
| DEAD | 目标不存在 | 新鲜死=WARN；**age≥30 天=CRIT（STALE）** |
| LOOP | 解引用回到已见过的自身 | CRIT |
| ESCAPE | 相对路径爬出扫描根 | WARN |
| EMPTY | 目标为空串（follow 必 ENOENT） | WARN |
| PERM | 祖先目录无权进入（非 root），存疑不判死 | WARN |
| DEEP / KERNELCAP | 跳数 ≥64 逻辑不解 / 跳数 ≥32 内核必 ELOOP | WARN |
| TEMP / SCOPE / MALFORM | 指向 /tmp、敏感区（组件级判定）、`//` 畸形目标 | WARN |
| OUTSIDE | 绝对路径指向扫描根之外（信息级，常见于 Homebrew Cask） | INFO（不升级） |
| OK | 一切正常 | AGED 只打标签不升级——链接年久是常态，「又老又死」才升级 |

**校准战绩**：对本机 Homebrew 全量 28505 条软链扫描=1.87s，零误报（worst=INFO）。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 干净（或仅 INFO/OK） |
| 1 | 用法错误（路径不存在等） |
| 2 | 有 WARN 级发现 |
| 3 | 有 CRIT 级发现 |
| 4 | 内部错误 |

## 设计不变量（selftest 全绿）

```bash
python3 linklens.py selftest   # 328 条不变量
```

覆盖：etime 五形态类比（链接年龄钳位 ≥0）、四类环（两跳/三跳/自指/绝对自指）、
50 跳可解 / 200 跳 DEEP、ESCAPE 三形态、TEMP/SCOPE 组件级判定、
AGED 不升级、基线三事件（NEW/GONE/RETARGET）、watch 两轮、演示沙箱确定性、
退出码映射、JSON/Markdown round-trip、max_scan 截断。

## 开发期狗粮清单（v1.0.0 自逮）

1. **`os.utime` 默认跟随软链**——造「古董断链」时改的是目标文件的时间，目标不存在直接
   FileNotFoundError。修：`follow_symlinks=False`。（自测还没绿就先崩，第一个真 bug）
2. **AGED 升级导致海量误报**——Homebrew 28030 条年久链接全是正常形态，`age` 单独存在
   不得参与分级。修：AGED 只打标签。「只有又老又死才 CRIT」。
3. **SCOPE 子串误伤**——`/opt/homebrew/etc/…` 里的 `etc` 误伤系统 `/etc` 判定，
   30 条 Homebrew 补全脚本链被冤枉。修：路径组件级判定（`etc` 必须是首组件）。
4. **逻辑可解 ≠ 内核能跟**——50 跳链 Python 循环能解开，但内核 `MAXSYMLINKS=32`，
   `open()` 必 ELOOP。新增 KERNELCAP 判据。
5. **max_scan 双计数**——生成器与消费方各记一遍导致截断判定失真。修：scan() 独家管理。
6. **signature 键是绝对路径**——测试里用 basename 取键直接 KeyError。
7. **基线换绑要先摘旧链**——`os.symlink` 不覆盖已存在目标（FileExistsError）。

## 演示（确定性沙箱）

```bash
python3 linklens.py demo            # 9 条链接覆盖全部状态，跑完自动清理
python3 linklens.py demo --keep     # 保留沙箱供检查
```

## 哨兵套件（同门工具）

cronguard（定时任务哨兵）→ logwhisperer（日志考古）→ debugkit（立案修复）→
porteye（端口暴露面）→ authguard（入口哨兵）→ callhome（外联哨兵）→
proclens（进程生命周期）→ **linklens（链接生命周期）**

## License

MIT
