# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-11-18

### Added
- 首个版本：断链考古与软链风险透镜
- scan：死链（新鲜/古董双级）、环链、越界链、空链、深链、KERNELCAP、TEMP/SCOPE 组件级判定
- baseline/check：链接签名基线与 NEW/GONE/RETARGET 三事件对照
- watch：轮次监视，抓链接换绑第一现场
- demo：确定性演示沙箱（9 链覆盖全部状态）
- selftest：328 条不变量
- 输出：human / JSON / Markdown 三格式；退出码 0/1/2/3/4 cron 友好

### Fixed（开发期狗粮，自测+真机双逮）
- os.utime 跟随软链导致造古董链必崩（follow_symlinks=False）
- AGED 单独存在不参与分级（Homebrew 28030 条误报教训）
- SCOPE 判定升到路径组件级（/opt/homebrew/etc 不再误伤 /etc）
- 新增 KERNELCAP：跳数≥32 内核必 ELOOP，逻辑可解≠能打开
- TEMP 改上下文判定：仅当目标在扫描根之外（demo 沙箱在 /tmp 下全员误挂的教训）
- max_scan 截断计数归 scan() 独家管理
- 自测内 signature 键名/换绑前摘链两处 fixture 错误

### Calibrated
- 本机 Homebrew 全量 28505 条软链：1.87s，零误报（worst=INFO, exit 0）
