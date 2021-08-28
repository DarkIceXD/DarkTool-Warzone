#include "../overlay/overlay.hpp"
#include "../config/config.h"

void overlay::menu()
{
	if (ImGui::Begin("DarkTool Warzone")) {
		ImGui::Checkbox("ESP", &cfg->esp.enabled);
		ImGui::SliderInt("Max Distance", &cfg->esp.max_distance, 0, 1000);
		ImGui::ColorEdit4("Box Color", &cfg->esp.box_color.r, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_InputRGB | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
		ImGui::Checkbox("Aimbot", &cfg->aimbot.enabled);
		if (ImGui::Button("Save config"))
			cfg->save();
		ImGui::End();
	}
}