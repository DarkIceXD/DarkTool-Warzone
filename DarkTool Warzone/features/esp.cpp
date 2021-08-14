#include "features.h"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../game/offsets.h"
#include "../game/decryption.h"
#include "../game/player.h"
#include "../math/math.hpp"
#include <iostream>

void features::esp(ImDrawList* d)
{
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
	for (int i = 0; i < 150; i++)
	{
		player p(client_base + ((uint64_t)i * offsets::player::size), i);
		if (!p.valid())
			continue;

		vector2 min, max;
		//p.get_bounding_box_fallback(min, max, camera_pos, refdef);
		if (math::world_to_screen(p.origin(), camera_pos, refdef, min))
			d->AddText({ min.x, min.y }, IM_COL32_WHITE, "enemy");
	}
}