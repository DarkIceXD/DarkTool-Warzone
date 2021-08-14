#include "../overlay/overlay.hpp"
#include "../game/config.h"

void overlay::menu()
{
	if (ImGui::Begin("DarkTool Warzone")) {
		ImGui::Checkbox("ESP", &config::esp);
		ImGui::End();
	}
}