#pragma once
#include "../imgui/imgui.h"
#include "../game/data.h"

namespace features {
	namespace esp {
		void draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos);
		void collect();
	}
	namespace aimbot {
		void draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos);
		void collect();
	}
}