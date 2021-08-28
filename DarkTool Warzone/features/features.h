#pragma once
#include "../imgui/imgui.h"
#include "data.h"

namespace features {
	namespace esp {
		void draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos);
		void collect(const uint64_t client_info, const uint64_t client_base);
	}
	namespace aimbot {
		void draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos, const vector2& camera_angles);
		void collect(const uint64_t client_info, const uint64_t client_base);
	}
}