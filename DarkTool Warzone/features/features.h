#pragma once
#include "../imgui/imgui.h"
#include "../game/data.h"

namespace features {
	void esp(const data::game& data, ImDrawList* d, const ref_def& refdef, const camera& camera);
	void aimbot(const data::game& data, ImDrawList* d, const ref_def& refdef, const camera& camera);
}