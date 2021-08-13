#include "../overlay/overlay.hpp"
#include "config.h"

void overlay::menu()
{
	if (ImGui::Begin("DarkTool Warzone")) {
		ImGui::Checkbox("ESP", &config::esp);
		ImGui::End();
	}
}