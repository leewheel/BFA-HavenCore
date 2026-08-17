-- By leewheel 2026-08-17
-- 修复狼人新手区"两个利亚姆"问题
--
-- sniff 实证（9.1.5 狼人新手任务全流程）：
--   1. 利亚姆是同一个 NPC（Low GUID 6248754），通过 CreateObject1 切换 entry（34850→34913→35551）
--   2. 出生 Phase=170（无 169！），由 aura 59073 施加
--   3. 34850 和 34913 都在 Phase 170 内，不是相位切换而是 entry 切换
--
-- 之前 DB 的问题：
--   - 34850 spawn 在 Phase 169，34913 spawn 在 Phase 170（两个独立 spawn）
--   - Phase 169 条件太宽松（14078 未奖励即激活）→ 新角色 169 激活 → 34850 可见
--   - Phase 170 条件要求 14091 已完成 → 新角色不满足 → 170 抑制 → 34913 不可见
--   - 但玩家实测仍看到 2 个利亚姆
--   - 另有孤儿条件 (26,169,4756) 因 4756 不在 phase_area 从未加载
--
-- 修复方案（贴合 sniff）：
--   1. 将 34850 spawn 的 phaseId 从 169 改为 170（与 sniff 一致：出生 Phase 170）
--   2. 删除 34913 的多余 spawn（官服不并存，entry 切换由 SmartAI 驱动）
--   3. 修改 Phase 170 @4755 条件：14091 未完成时激活（贴合 sniff 出生即 Phase 170）
--   4. 修复 Phase 169 @4755 孤儿条件：SourceEntry 4756→4755 使条件正确加载
--
-- 备份：TempFiles/phase169_170_conditions_backup_20260817.tsv

-- 1. 34850 spawn phaseId 169→170（贴合 sniff：出生 Phase 170）
UPDATE `creature` SET `phaseId` = 170 WHERE `guid` = 20556224 AND `id` = 34850;

-- 2. 删除 34913 多余 spawn（官服不并存，entry 切换由 SmartAI 驱动）
DELETE FROM `creature` WHERE `guid` = 20556364 AND `id` = 34913;

-- 3. Phase 170 @4755 条件：14091 未完成时激活（原为 14091 已完成，Neg=0）
UPDATE `conditions`
SET `NegativeCondition` = 1,
    `Comment` = 'Phase 170 active while 14091 not complete (fix: worgen start phase, per sniff) - by leewheel'
WHERE `SourceTypeOrReferenceId` = 26
  AND `SourceGroup` = 170
  AND `SourceEntry` = 4755
  AND `ConditionTypeOrReference` = 28
  AND `ConditionValue1` = 14091;

-- 4. Phase 169 孤儿条件修复：SourceEntry 4756→4755
UPDATE `conditions`
SET `SourceEntry` = 4755,
    `Comment` = 'Set Phase 169 until Quest 14091 complete (fix: 4756 not in phase_area, use 4755) - by leewheel'
WHERE `SourceTypeOrReferenceId` = 26
  AND `SourceGroup` = 169
  AND `SourceEntry` = 4756
  AND `ConditionTypeOrReference` = 28
  AND `ConditionValue1` = 14091;
-- End By leewheel
