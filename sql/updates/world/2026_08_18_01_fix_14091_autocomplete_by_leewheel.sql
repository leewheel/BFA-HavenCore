-- 修复任务 14091（事有蹊跷）接取即自动完成导致相位 170 消失 bug
-- 原始问题：14091 没有任何 quest_objectives 条目，导致 CanCompleteQuest 判定为可完成，接取即完成
-- 相位 170 @4755 条件要求"14091 未完成"，任务完成后相位被移除，所有守卫消失
-- 修复方案：添加一个 TALKTO 目标（对利亚姆说话），让任务保持未完成状态，直到玩家对话提交
-- 目标信息：Type=3（QUEST_OBJECTIVE_TALKTO），ObjectID=34913（利亚姆王子，任务提交者），Amount=1
-- Author: leewheel
-- Date: 2026-08-18

INSERT INTO quest_objectives (ID, QuestID, Type, `Order`, StorageIndex, ObjectID, Amount, Flags, Flags2, ProgressBarWeight, Description, VerifiedBuild)
VALUES (4987101, 14091, 3, 0, 0, 34913, 1, 0, 0, 0.0, '和利亚姆王子对话', 41793);
