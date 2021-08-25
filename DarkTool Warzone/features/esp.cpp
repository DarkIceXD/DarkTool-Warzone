#include "features.h"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../game/config.h"
#include "../game/offsets.h"
#include "../game/decryption.h"
#include "../game/player.h"
#include "../math/math.hpp"
#include <string>
#include <iostream>

int local_index(const uint64_t client_info)
{
	const auto local_index = driver::read<uintptr_t>(client_info + offsets::local_index);
	return driver::read<int>(local_index + offsets::local_index_pos);
}

void features::esp(ImDrawList* d)
{
	if (!config::esp::enabled)
		return;

	static const auto client_info = decryption::decrypt_client_info(globals::base, globals::peb);
	if (!client_info)
	{
		std::cout << "client_info was null\n";
		return;
	}

	static const auto client_base = decryption::decrypt_client_base(client_info, globals::base, globals::peb);
	if (!client_base)
	{
		std::cout << "client_base was null\n";
		return;
	}

	const auto refdef = driver::read<ref_def>(decryption::get_ref_def(offsets::ref_def));
	const auto camera_pos = math::get_camera_position();
	const auto local_i = local_index(client_info);
	const player local(client_base + ((uint64_t)local_i * offsets::player::size), local_i);
	const auto local_origin = local.origin();
	const auto local_team = local.team();
	for (int i = 0; i < 150; i++)
	{
		player p(client_base + ((uint64_t)i * offsets::player::size), i);
		if (!p.valid())
			continue;

		if (p.team() == local_team)
			continue;

		const auto origin = p.origin();
		const auto meters = (int)math::units_to_m((origin - local_origin).length());
		if (config::esp::max_distance && meters > config::esp::max_distance)
			continue;

		vector2 feet;
		if (math::world_to_screen(origin, camera_pos, refdef, feet))
		{
			const auto meters_text = std::string("[") + std::to_string(meters) + " m]";
			const auto size = ImGui::CalcTextSize(meters_text.c_str());
			d->AddText({ feet.x - size.x / 2, feet.y }, IM_COL32_WHITE, meters_text.c_str());
		}

		vector2 min, max;
		if (p.get_bounding_box_fallback(min, max, origin, camera_pos, refdef))
			d->AddRect({ min.x, min.y }, { max.x, max.y }, IM_COL32(255, 0, 0, 255));
	}
}