#include "features.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../math/math.hpp"
#include "../game/decryption.h"

void aim_at(const vector2& screen, const bool absolute)
{
	INPUT input = { 0 };
	input.type = INPUT_MOUSE;
	if (absolute)
	{
		input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
		input.mi.dx = screen.x * (65536.f / GetSystemMetrics(SM_CXSCREEN));
		input.mi.dy = screen.y * (65536.f / GetSystemMetrics(SM_CYSCREEN));
	}
	else
	{
		input.mi.dwFlags = MOUSEEVENTF_MOVE;
		input.mi.dx = screen.x;
		input.mi.dy = screen.y;
	}
	SendInput(1, &input, sizeof(input));
}

void features::aimbot(const data::game& data, ImDrawList* d, const ref_def& refdef, const camera& camera)
{
	cfg->aimbot.bind.run();
	if (!cfg->aimbot.bind.enabled)
		return;

	const auto tan_half_fov = refdef.view.tan_half_fov.length();
	const vector2 middle(refdef.width / 2, refdef.height / 2);
	auto smallest_fov = FLT_MAX;
	vector2 best_hitbox;
	for (const auto& player : data.players)
	{
		if (!player.valid)
			break;

		if (cfg->aimbot.max_distance && player.distance > cfg->aimbot.max_distance)
			break;

		if (player.team == data.local_player.team)
			continue;

		if (cfg->aimbot.visibility_check && !player.visible)
			continue;

		if (!cfg->aimbot.aim_at_downed_players && player.stance == player::stance::downed)
			continue;

		for (int i = 0; i < player.bones_screen.size(); i++)
		{
			const auto& bone = player.bones_screen[i];
			if (!bone.valid)
				continue;

			if (!cfg->aimbot.is_bone_enabled(data::player_data::index_to_bone(i)))
				continue;

			const auto fov = math::pixels_to_fov((bone.screen - middle).length(), tan_half_fov, middle.x);
			if (fov < smallest_fov)
			{
				smallest_fov = fov;
				best_hitbox = bone.screen;
			}
		}
	}

	if (smallest_fov >= FLT_MAX || smallest_fov > cfg->aimbot.fov)
		return;

	if (cfg->aimbot.show_aim_spot)
	{
		d->AddLine(best_hitbox - vector2(5, 5), best_hitbox + vector2(5, 5), IM_COL32_WHITE);
		d->AddLine(best_hitbox - vector2(5, -5), best_hitbox + vector2(5, -5), IM_COL32_WHITE);
	}

	const auto diff = best_hitbox - middle;
	auto dx = diff * (3.f / cfg->aimbot.game_sensitivity);
	const auto fov = math::pixels_to_fov(diff.length(), tan_half_fov, middle.x);
	if (fov > 2)
		dx /= cfg->aimbot.smoothness;
	aim_at(dx, false);
}