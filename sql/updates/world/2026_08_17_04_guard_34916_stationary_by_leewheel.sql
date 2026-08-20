-- By leewheel 2026-08-17
-- 修复 NPC 34916（Gilneas City Guard）脱战（无目标）时胡乱转身问题
-- 根因：MovementType=1（随机游走）+ spawndist=10，守卫在击杀狼人后无目标时
--       会在原地随机转向移动，视觉上像"想攻击什么又失去目标"
-- 官服 sniff 依据：官服守卫从不移动（MovementSplineMove=False，Destination=Position），
--       击杀目标后原地站桩，仅朝向敌人
-- 正确方案：MovementType 改为 0（站桩），spawndist 改为 0
-- 执行：将守卫 34916 全部刷怪点改为站桩

UPDATE creature SET spawndist = 0, MovementType = 0 WHERE id = 34916;

-- End By leewheel
