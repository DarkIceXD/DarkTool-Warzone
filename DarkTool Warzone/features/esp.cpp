#include "features.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../math/math.hpp"
#include <string>

void features::esp::draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos)
{
	cfg->esp.bind.run();
	if (!cfg->esp.bind.enabled)
		return;

	const auto color = cfg->esp.box_color.to_u32();
	for (const auto& player : data::players)
	{
		if (!player.esp_valid)
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

void features::esp::collect()
{
	if (!cfg->esp.bind.enabled)
		return;

	for (auto& player : data::players)
	{
		if (!player.valid)
			continue;

		if (cfg->esp.max_distance && player.distance > cfg->esp.max_distance)
			continue;

		player.esp_valid = true;
	}
}