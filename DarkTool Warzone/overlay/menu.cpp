#include "overlay.hpp"

void overlay::menu()
{
	if (ImGui::Begin("")) {
		ImGui::Text("Hello world");
		ImGui::End();
	}
}