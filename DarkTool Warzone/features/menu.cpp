#include "../overlay/overlay.hpp"
#include "../config/config.h"

namespace ImGui {
	void KeyBind(const char* label, int* selection, int* key_bind, bool* did_find) {
		PushID(label);
		Combo(label, selection, "Keybind disabled\0Toggle on key\0Active on hold\0");
		if (!*did_find) {
			PushStyleColor(ImGuiCol_Button, ImVec4(0, 0.6f, 0, 1));
			PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.6f, 0.3f, 1));
		}
		const auto clicked = Button("Rebind");
		if (!*did_find)
			PopStyleColor(2);
		if (clicked)
		{
			*did_find = !*did_find;
			for (int i = 0; i < 0xFE; i++)
				GetAsyncKeyState(i);
		}
		SameLine();
		Text("Bind: %d", *key_bind);
		if (!*did_find)
		{
			if (GetAsyncKeyState(VK_DELETE))
			{
				*key_bind = 0;
				*did_find = true;
			}
			else
			{
				for (int i = 0; i < 0xFE; i++)
				{
					if (GetAsyncKeyState(i))
					{
						*key_bind = i;
						*did_find = true;
						break;
					}
				}
			}
		}
		PopID();
	}
}

void overlay::menu()
{
	if (ImGui::Begin("DarkTool Warzone")) {
		ImGui::PushItemWidth(-200);
		if (ImGui::BeginTabBar("tabs"))
		{
			if (ImGui::BeginTabItem("ESP"))
			{
				ImGui::Checkbox("Enabled", &cfg->esp.bind.enabled);
				static auto esp_found = true;
				ImGui::KeyBind("ESP", &cfg->esp.bind.type, &cfg->esp.bind.key_bind, &esp_found);
				ImGui::SliderInt("Max Distance", &cfg->esp.max_distance, 0, 1000);
				ImGui::ColorEdit4("Box Color", &cfg->esp.box.base.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
				ImGui::ColorEdit4("Box Color Visible", &cfg->esp.box.visible.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
				ImGui::ColorEdit4("Box Color Downed", &cfg->esp.box.downed.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
				ImGui::ColorEdit4("Skeleton Color", &cfg->esp.skeleton.base.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
				ImGui::ColorEdit4("Skeleton Color Visible", &cfg->esp.skeleton.visible.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
				ImGui::ColorEdit4("Skeleton Color Downed", &cfg->esp.skeleton.downed.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
				ImGui::SliderInt("Show Nearest Players", &cfg->esp.show_nearest_players, 0, 1000);
				ImGui::Combo("Show Nearest Players Type", &cfg->esp.show_nearest_players_type, "Table\0Radar\0");
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Aimbot"))
			{
				ImGui::Checkbox("Enabled", &cfg->aimbot.bind.enabled);
				static auto aimbot_found = true;
				ImGui::KeyBind("Aimbot", &cfg->aimbot.bind.type, &cfg->aimbot.bind.key_bind, &aimbot_found);
				ImGui::SliderFloat("Game Sensitivity", &cfg->aimbot.game_sensitivity, 0, 20);
				ImGui::SliderInt("Max Distance", &cfg->aimbot.max_distance, 0, 1000);
				ImGui::SliderFloat("Fov", &cfg->aimbot.fov, 1, 90);
				ImGui::SliderFloat("Smoothness", &cfg->aimbot.smoothness, 1, 10);
				if (ImGui::BeginTable("hitbox", 2, ImGuiTableFlags_SizingStretchSame))
				{
					ImGui::TableSetupColumn("Hitbox");
					ImGui::TableSetupColumn("Enabled");
					ImGui::TableHeadersRow();
					ImGui::TableNextRow();
					ImGui::PushID(0);
					ImGui::TableNextColumn();
					ImGui::TextUnformatted("Head");
					ImGui::TableNextColumn();
					ImGui::Checkbox("##normal", &cfg->aimbot.head);
					ImGui::PopID();
					ImGui::PushID(1);
					ImGui::TableNextColumn();
					ImGui::TextUnformatted("Chest");
					ImGui::TableNextColumn();
					ImGui::Checkbox("##normal", &cfg->aimbot.chest);
					ImGui::PopID();
					ImGui::EndTable();
				}
				ImGui::Checkbox("Visibility Check", &cfg->aimbot.visibility_check);
				ImGui::Checkbox("Aim at downed players", &cfg->aimbot.aim_at_downed_players);
				ImGui::Checkbox("Show aim spot", &cfg->aimbot.show_aim_spot);
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Config"))
			{
				if (ImGui::Button("Save config"))
					cfg->save();
				ImGui::EndTabItem();
			}
			ImGui::EndTabBar();
		}
		ImGui::PopItemWidth();
	}
	ImGui::End();
}