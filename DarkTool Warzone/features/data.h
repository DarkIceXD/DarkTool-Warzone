#pragma once
#include "../imgui/imgui.h"
#include <array>

namespace data {
	struct player_data {
		ImVec2 min, max, feet;
		int distance;
		bool valid;
	};

	inline std::array<player_data, 150> players;
	void collect();
}