-- 增加NPC 34913（利亚姆王子）在吉尔尼斯商人广场的刷点
-- 问题：任务14091缺少提交NPC，导致任务无法完成
-- 位置基于Sniff: Map=654 Zone=4755 Area=4756 PhaseId=170
-- Author: leewheel
-- Date: 2026-08-18

INSERT INTO creature (guid, id, map, zoneId, areaId, spawnDifficulties, phaseUseFlags, PhaseId, PhaseGroup, terrainSwapMap, modelid, equipment_id, position_x, position_y, position_z, orientation, spawntimesecs, spawndist, currentwaypoint, curhealth, curmana, MovementType, npcflag, unit_flags, unit_flags2, unit_flags3, dynamicflags, ScriptName, VerifiedBuild)
VALUES (20556413, 34913, 654, 4755, 4756, '0', 0, 170, 0, -1, 36770, 0, -1440.4159, 1403.8652, 35.68091, 0.0, 120, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, '', 41793);