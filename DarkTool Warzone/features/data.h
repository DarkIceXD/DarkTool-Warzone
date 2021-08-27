#pragma once
#include "../imgui/imgui.h"
#include "../game/player.h"
#include <array>

namespace data {
	struct player_data {
		vector3 origin;
		character_stance stance;
		int distance;
		bool valid;
	};

	inline std::array<player_data, 150> players;
	void collect();
}