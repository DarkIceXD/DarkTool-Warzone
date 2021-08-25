#include "../overlay/overlay.hpp"
#include "../game/config.h"

void overlay::menu()
{
	if (ImGui::Begin("DarkTool Warzone")) {
		ImGui::Checkbox("ESP", &config::esp::enabled);
		ImGui::SliderInt("Max Distance", &config::esp::max_distance, 0, 1000);
		ImGui::End();
	}
}