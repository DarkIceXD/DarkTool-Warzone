#include "features.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../math/math.hpp"
#include "../game/decryption.h"
#include "../game/globals.h"

static uint64_t bone_base = 0;
static vector3 bone_base_pos;

float fov(const vector2& screen, const float screen_width, const float game_fov)
{
	return (screen / screen_width).length() * game_fov / 2;
}

void aim_at(const float x, const float y, const bool absolute)
{
	INPUT input = { 0 };
	input.type = INPUT_MOUSE;
	if (absolute)
	{
		input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
		input.mi.dx = x * (65536.f / GetSystemMetrics(SM_CXSCREEN));
		input.mi.dy = y * (65536.f / GetSystemMetrics(SM_CYSCREEN));
	}
	else
	{
		input.mi.dwFlags = MOUSEEVENTF_MOVE;
		input.mi.dx = x;
		input.mi.dy = y;
	}
	SendInput(1, &input, sizeof(input));
}

void features::aimbot::draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos)
{
	cfg->aimbot.bind.run();
	if (!cfg->aimbot.bind.enabled)
		return;

	if (!bone_base)
		return;

	auto smallest_fov = FLT_MAX;
	int best_index;
	const vector2 middle(refdef.width / 2, refdef.height / 2);
	for (int i = 0; i < data::players.size(); i++)
	{
		const auto& player = data::players[i];
		if (!player.aimbot_valid)
			continue;

		vector2 feet;
		if (!math::world_to_screen(player.origin + vector3(0, 0, 40), camera_pos, refdef, feet))
			continue;

		const auto fov = (feet - middle).length();
		if (fov < smallest_fov)
		{
			smallest_fov = fov;
			best_index = i;
		}
	}

	if (smallest_fov >= FLT_MAX || smallest_fov > cfg->aimbot.max_pixels)
		return;

	const auto bone_index = decryption::get_bone_index(best_index, globals::base);
	const auto bone_ptr = player::get_bone_ptr(bone_base, bone_index);
	if (!bone_ptr)
		return;

	const auto bone_pos = player::get_bone_position(bone_ptr, bone_base_pos, ((cfg->aimbot.hitbox == 0) ? 5 : 7));
	vector2 screen_pos;
	if (!math::world_to_screen(bone_pos, camera_pos, refdef, screen_pos))
		return;

	if (cfg->aimbot.show_aim_spot)
	{
		d->AddLine({ screen_pos.x - 5, screen_pos.y - 5 }, { screen_pos.x + 5, screen_pos.y + 5 }, IM_COL32_WHITE);
		d->AddLine({ screen_pos.x - 5, screen_pos.y + 5 }, { screen_pos.x + 5, screen_pos.y - 5 }, IM_COL32_WHITE);
	}
	screen_pos -= middle;
	aim_at(screen_pos.x, screen_pos.y, false);
}

void features::aimbot::collect(const uint64_t client_info)
{
	if (!cfg->aimbot.bind.enabled)
		return;

	auto any_valid = false;
	for (auto& player : data::players)
	{
		if (!player.valid)
			continue;

		if (cfg->aimbot.max_distance && player.distance > cfg->aimbot.max_distance)
			continue;

		if (!cfg->aimbot.aim_at_downed_players && player.stance == character_stance::downed)
			continue;

		player.aimbot_valid = true;
		any_valid = true;
	}

	if (any_valid)
	{
		bone_base = decryption::decrypt_bone_base(globals::base, globals::peb);
		bone_base_pos = player::get_bone_base_pos(client_info);
	}
}