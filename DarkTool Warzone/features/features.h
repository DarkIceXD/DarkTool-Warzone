#pragma once
#include "../imgui/imgui.h"
#include "../game/data.h"

namespace features {
	namespace esp {
		void draw(const data::game& data, ImDrawList* d, const ref_def& refdef, const camera& camera);
		void update(data::game& data);
	}
	namespace aimbot {
		void draw(const data::game& data, ImDrawList* d, const ref_def& refdef, const camera& camera);
		void update(data::game& data);
	}
}