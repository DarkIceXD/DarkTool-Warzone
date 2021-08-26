#include "features.h"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../game/config.h"
#include "../game/offsets.h"
#include "../game/decryption.h"
#include "../game/player.h"
#include "../math/math.hpp"
#include <string>

void features::esp::draw(ImDrawList* d)
{
	if (!config::esp::enabled)
		return;

	for (const auto& player : data::players)
	{
		if (!player.valid)
			continue;

		const auto meters_text = std::string("[") + std::to_string(player.distance) + " m]";
		const auto size = ImGui::CalcTextSize(meters_text.c_str());
		d->AddText({ player.feet.x - size.x / 2, player.feet.y }, IM_COL32_WHITE, meters_text.c_str());
		d->AddRect({ player.min.x, player.min.y }, { player.max.x, player.max.y }, IM_COL32(255, 0, 0, 255));
	}
}

void features::esp::collect(const uint64_t client_info, const uint64_t client_base)
{
	if (!config::esp::enabled)
		return;

	const auto local_index = player::get_local_index(client_info);
	if (local_index < 0)
		return;

	const player local_player(client_base, local_index);
	const auto local_origin = local_player.origin();
	const auto local_team = local_player.team();
	const auto refdef = driver::read<ref_def>(decryption::get_ref_def(globals::base, offsets::refdef));
	const auto camera_pos = math::get_camera_position();
	for (int i = 0; i < 150; i++)
	{
		auto& player_data = data::players[i];
		player_data.valid = false;
		const player p(client_base, i);
		if (!p.valid())
			continue;

		if (p.team() == local_team)
			continue;

		const auto origin = p.origin();
		player_data.distance = (int)math::units_to_m((origin - local_origin).length());
		if (config::esp::max_distance && player_data.distance > config::esp::max_distance)
			continue;

		vector2 feet;
		if (!math::world_to_screen(origin, camera_pos, refdef, feet))
			continue;

		player_data.feet = { feet.x, feet.y };

		vector2 min, max;
		if (!p.get_bounding_box_fallback(min, max, origin, camera_pos, refdef))
			continue;

		player_data.min = { min.x, min.y };
		player_data.max = { max.x, max.y };

		player_data.valid = true;
	}
}