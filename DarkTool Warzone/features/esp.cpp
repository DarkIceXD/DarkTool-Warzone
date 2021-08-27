#include "features.h"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../config/config.h"
#include "../game/offsets.h"
#include "../game/decryption.h"
#include "../game/player.h"
#include "../math/math.hpp"
#include <string>

void features::esp::draw(ImDrawList* d)
{
	if (!cfg->esp.enabled)
		return;

	vector3 camera_pos;
	if (!math::get_camera_position(camera_pos))
		return;

	const auto ref_def_ptr = decryption::get_ref_def(globals::base, offsets::refdef);
	if (!ref_def_ptr)
		return;

	const auto refdef = driver::read<ref_def>(ref_def_ptr);
	const auto color = cfg->esp.box_color.to_u32();
	for (const auto& player : data::players)
	{
		if (!player.valid)
			continue;

		vector2 feet;
		if (math::world_to_screen(player.origin, camera_pos, refdef, feet))
		{
			const auto meters_text = std::string("[") + std::to_string(player.distance) + " m]";
			const auto size = ImGui::CalcTextSize(meters_text.c_str()).x;
			d->AddText({ feet.x - size / 2, feet.y }, IM_COL32_WHITE, meters_text.c_str());
		}

		vector2 min, max;
		if (player::get_bounding_box_fallback(min, max, player.origin, player.stance, camera_pos, refdef))
			d->AddRect({ min.x, min.y }, { max.x, max.y }, color);
	}
}

void features::esp::collect(const uint64_t client_info, const uint64_t client_base)
{
	if (!cfg->esp.enabled)
		return;

	const auto local_index = player::get_local_index(client_info);
	if (local_index < 0)
		return;

	const player local_player(client_base, local_index);
	const auto local_origin = local_player.get_origin();
	const auto local_team = local_player.get_team();
	for (int i = 0; i < 150; i++)
	{
		auto& player_data = data::players[i];
		player_data.valid = false;
		const player p(client_base, i);
		if (!p.is_valid())
			continue;

		if (p.get_team() == local_team)
			continue;

		player_data.origin = p.get_origin();
		player_data.distance = (int)math::units_to_m((player_data.origin - local_origin).length());
		if (cfg->esp.max_distance && player_data.distance > cfg->esp.max_distance)
			continue;

		player_data.stance = p.get_stance();
		player_data.valid = true;
	}
}