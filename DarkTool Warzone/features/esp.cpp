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
	const auto visible = cfg->esp.box_color_visible.to_u32();
	const auto downed = cfg->esp.box_color_downed.to_u32();
	for (const auto& player : data::players)
	{
		if (!player.esp_valid)
			continue;

		vector2 min, max;
		if (!player::get_bounding_box_fallback(min, max, player.origin, player.stance, camera_pos, refdef))
			continue;

		const auto player_color = player.stance == character_stance::downed ? downed : (player.visible ? visible : color);
		d->AddRect({ min.x, min.y }, { max.x, max.y }, player_color);
		const auto middle = (max.x - min.x) / 2 + min.x;
		char meters_text[16];
		snprintf(meters_text, sizeof(meters_text), "[%dm]", player.distance);
		//const auto meters_text = std::string("[") + std::to_string(player.distance) + " m]";
		const auto distance_size = ImGui::CalcTextSize(meters_text);
		d->AddText({ middle - distance_size.x / 2, min.y }, IM_COL32_WHITE, meters_text);
		const auto name_size = ImGui::CalcTextSize(player.name);
		d->AddText({ middle - name_size.x / 2, max.y - name_size.y }, IM_COL32_WHITE, player.name);
		const ImVec2 hp_min = { max.x + 2, min.y };
		const ImVec2 hp_max = { hp_min.x + 3, hp_min.y + (max.y - min.y) * player.health };
		d->AddRectFilled(hp_min, hp_max, rgb::scale({ 0, 1, 0, 1 }, { 1, 0, 0, 1 }, player.health).to_u32());
		d->AddRect(hp_min, hp_max, IM_COL32_BLACK);
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