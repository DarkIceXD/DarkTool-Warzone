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

	const auto box_base_color = cfg->esp.box.base.to_u32();
	const auto box_visible_color = cfg->esp.box.visible.to_u32();
	const auto box_downed_color = cfg->esp.box.downed.to_u32();
	const auto skeleton_base_color = cfg->esp.skeleton.base.to_u32();
	const auto skeleton_visible_color = cfg->esp.skeleton.visible.to_u32();
	const auto skeleton_downed_color = cfg->esp.skeleton.downed.to_u32();
	for (const auto& player : data::players)
	{
		if (!player.esp_valid)
			continue;

		vector2 min, max;
		if (!player::get_bounding_box_fallback(min, max, player.origin, player.stance, camera_pos, refdef))
			continue;

		const auto box_color = player.stance == player::stance::downed ? box_downed_color : (player.visible ? box_visible_color : box_base_color);
		d->AddRect(min, max, box_color);
		const auto middle = (max.x - min.x) / 2 + min.x;
		char meters_text[16];
		snprintf(meters_text, sizeof(meters_text), "[%dm]", player.distance);
		const auto distance_size = ImGui::CalcTextSize(meters_text);
		d->AddText({ middle - distance_size.x / 2, min.y }, IM_COL32_WHITE, meters_text);
		const auto name_size = ImGui::CalcTextSize(player.name);
		d->AddText({ middle - name_size.x / 2, max.y - name_size.y }, IM_COL32_WHITE, player.name);
		const ImVec2 hp_min = { max.x + 2, min.y };
		const ImVec2 hp_max = { hp_min.x + 3, hp_min.y + (max.y - min.y) * player.health };
		d->AddRectFilled(hp_min, hp_max, rgb::scale({ 0, 1, 0, 1 }, { 1, 0, 0, 1 }, player.health).to_u32());
		d->AddRect(hp_min, hp_max, IM_COL32_BLACK);

		const auto skeleton_color = player.stance == player::stance::downed ? skeleton_downed_color : (player.visible ? skeleton_visible_color : skeleton_base_color);
		if ((skeleton_color & 0xFF000000) && math::units_to_m((player.bones[0] - player.origin).length()) <= 2)
			for (const auto& bone_connection : player::bone_connections)
			{
				vector2 a, b;
				if (!math::world_to_screen(player.get_bone(bone_connection.first), camera_pos, refdef, a) ||
					!math::world_to_screen(player.get_bone(bone_connection.second), camera_pos, refdef, b))
					continue;

				d->AddLine(a, b, skeleton_color);
			}
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