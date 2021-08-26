#pragma once
#include "../imgui/imgui.h"
#include "data.h"

namespace features {
	namespace esp {
		void draw(ImDrawList* d);
		void collect(const uint64_t client_info, const uint64_t client_base);
	}
}