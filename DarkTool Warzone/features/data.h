#pragma once
#include "../game/player.h"
#include <array>

namespace data {
	struct player_data {
		vector3 origin;
		character_stance stance;
		int distance;
		bool valid;
		bool esp_valid;
		bool aimbot_valid;
	};
	struct local_player_data {
		vector3 origin;
		bool valid;
	};

	inline std::array<player_data, 150> players;
	inline local_player_data local_player;
	void collect();
}