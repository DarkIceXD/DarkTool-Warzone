#include "features.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../math/math.hpp"

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
		char name[64];
		snprintf(name, sizeof(name), "%s #%d", player.name, player.team);
		const auto name_size = ImGui::CalcTextSize(name);
		d->AddText({ middle - name_size.x / 2, max.y - name_size.y }, IM_COL32_WHITE, name);
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
	if (cfg->esp.show_nearest_players)
	{
		static int corner = 0;
		ImGuiIO& io = ImGui::GetIO();
		ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav;
		if (corner != -1)
		{
			const ImGuiViewport* viewport = ImGui::GetMainViewport();
			ImVec2 work_pos = viewport->WorkPos;
			ImVec2 work_size = viewport->WorkSize;
			ImVec2 window_pos, window_pos_pivot;
			constexpr auto padding = 10;
			window_pos.x = (corner & 1) ? (work_pos.x + work_size.x - padding) : (work_pos.x + padding);
			window_pos.y = (corner & 2) ? (work_pos.y + work_size.y - padding) : (work_pos.y + padding);
			window_pos_pivot.x = (corner & 1) ? 1.0f : 0.0f;
			window_pos_pivot.y = (corner & 2) ? 1.0f : 0.0f;
			ImGui::SetNextWindowPos(window_pos, ImGuiCond_Always, window_pos_pivot);
			window_flags |= ImGuiWindowFlags_NoMove;
		}
		ImGui::SetNextWindowBgAlpha(0.35f);
		if (ImGui::Begin("Nearest Enemies", nullptr, window_flags))
		{
			if (ImGui::BeginTable("enemies", 3, ImGuiTableFlags_SizingStretchSame))
			{
				ImGui::TableSetupColumn("Distance");
				ImGui::TableSetupColumn("Name");
				ImGui::TableSetupColumn("Team");
				ImGui::TableHeadersRow();
				for (const auto& player : data::sorted_players)
				{
					if (!player.valid)
						break;

					if (player.distance > cfg->esp.show_nearest_players)
						break;

					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::Text("%d", player.distance);
					ImGui::TableNextColumn();
					ImGui::Text(player.name);
					ImGui::TableNextColumn();
					ImGui::Text("%d", player.team);
					ImGui::TableNextColumn();
				}
				ImGui::EndTable();
			}
			if (ImGui::BeginPopupContextWindow())
			{
				if (ImGui::MenuItem("Custom", NULL, corner == -1)) corner = -1;
				if (ImGui::MenuItem("Top-left", NULL, corner == 0)) corner = 0;
				if (ImGui::MenuItem("Top-right", NULL, corner == 1)) corner = 1;
				if (ImGui::MenuItem("Bottom-left", NULL, corner == 2)) corner = 2;
				if (ImGui::MenuItem("Bottom-right", NULL, corner == 3)) corner = 3;
				ImGui::EndPopup();
			}
		}
		ImGui::End();
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