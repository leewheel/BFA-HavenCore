-- By leewheel 2026-08-17
-- 修复 NPC 34916（Gilneas City Guard）无目标时胡乱转身问题
-- 根因：错误配置 SmartAI 每 3 秒在 OOC 阶段强制搜索攻击目标 + MoveInLineOfSight 频繁触发 → 不断转头尝试攻击然后失去目标，视觉上异常混乱
-- 正确方案：使用标准守卫脚本 guard_generic + GUARD 标记，走官方仇恨系统，只在敌人进入范围时自动攻击
-- 执行：
--   1. 删除错误 SmartAI 配置
--   2. 设置 ScriptName 为 guard_generic，添加 GUARD 标记 (CREATURE_FLAG_EXTRA_GUARD = 0x8000 = 32768)

DELETE FROM smart_scripts WHERE entryorguid = 34916 AND source_type = 0;
UPDATE creature_template SET ScriptName = 'guard_generic', flags_extra = flags_extra | 0x8000 WHERE entry = 34916;

-- End By leewheel
