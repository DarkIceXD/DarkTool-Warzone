#include "features.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../math/math.hpp"
#include "../game/decryption.h"
#include "../game/globals.h"

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

void features::aimbot::draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos)
{
	cfg->aimbot.bind.run();
	if (!cfg->aimbot.bind.enabled)
		return;

	const auto tan_half_fov = refdef.view.tan_half_fov.length();
	const vector2 middle(refdef.width / 2, refdef.height / 2);
	auto smallest_fov = FLT_MAX;
	vector2 best_hitbox;
	for (int i = 0; i < data::players.size(); i++)
	{
		const auto& player = data::players[i];
		if (!player.aimbot_valid)
			continue;

		vector2 hitbox;
		if (!math::world_to_screen(player.get_bone(((cfg->aimbot.hitbox == 0) ? player::bone::chest : player::bone::head)), camera_pos, refdef, hitbox))
			continue;

		const auto fov = math::pixels_to_fov((hitbox - middle).length(), tan_half_fov, middle.x);
		if (fov < smallest_fov)
		{
			smallest_fov = fov;
			best_hitbox = hitbox;
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
	auto dx = diff * (7.f / cfg->aimbot.game_sensitivity);
	const auto fov = math::pixels_to_fov(diff.length(), tan_half_fov, middle.x);
	if (fov > 2)
		dx /= cfg->aimbot.smoothness;
	aim_at(dx, false);
}

void features::aimbot::collect()
{
	if (!cfg->aimbot.bind.enabled)
		return;

	for (auto& player : data::players)
	{
		if (!player.valid)
			continue;

		if (cfg->aimbot.visibility_check && !player.visible)
			continue;

		if (cfg->aimbot.max_distance && player.distance > cfg->aimbot.max_distance)
			continue;

		if (!cfg->aimbot.aim_at_downed_players && player.stance == player::stance::downed)
			continue;

		player.aimbot_valid = true;
	}
}