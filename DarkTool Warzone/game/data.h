#pragma once
#include "player.h"
#include <array>

namespace data {
	struct player_data {
		std::array<vector3, 21> bones;
		vector3 origin;
		player::stance stance;
		int distance;
		int team;
		float health;
		char name[0x24];
		bool visible;
		bool valid;
		bool esp_valid;
		bool aimbot_valid;
		static constexpr size_t bone_to_index(const player::bone bone) noexcept
		{
			switch (bone)
			{
			case player::bone::head:
				return 0;
			case player::bone::neck:
				return 1;
			case player::bone::chest:
				return 2;
			case player::bone::mid:
				return 3;
			case player::bone::tummy:
				return 4;
			case player::bone::right_hand1:
				return 5;
			case player::bone::right_hand2:
				return 6;
			case player::bone::right_hand3:
				return 7;
			case player::bone::right_hand4:
				return 8;
			case player::bone::left_hand1:
				return 9;
			case player::bone::left_hand2:
				return 10;
			case player::bone::left_hand3:
				return 11;
			case player::bone::left_hand4:
				return 12;
			case player::bone::left_foot1:
				return 13;
			case player::bone::left_foot2:
				return 14;
			case player::bone::left_foot3:
				return 15;
			case player::bone::left_foot4:
				return 16;
			case player::bone::right_foot1:
				return 17;
			case player::bone::right_foot2:
				return 18;
			case player::bone::right_foot3:
				return 19;
			case player::bone::right_foot4:
				return 20;
			default:
				return 0;
			}
		}
		constexpr const vector3& get_bone(const player::bone bone) const noexcept
		{
			return bones[bone_to_index(bone)];
		}
		static constexpr player::bone index_to_bone(const size_t index) noexcept
		{
			switch (index)
			{
			case 0:
				return player::bone::head;
			case 1:
				return player::bone::neck;
			case 2:
				return player::bone::chest;
			case 3:
				return player::bone::mid;
			case 4:
				return player::bone::tummy;
			case 5:
				return player::bone::right_hand1;
			case 6:
				return player::bone::right_hand2;
			case 7:
				return player::bone::right_hand3;
			case 8:
				return player::bone::right_hand4;
			case 9:
				return player::bone::left_hand1;
			case 10:
				return player::bone::left_hand2;
			case 11:
				return player::bone::left_hand3;
			case 12:
				return player::bone::left_hand4;
			case 13:
				return player::bone::left_foot1;
			case 14:
				return player::bone::left_foot2;
			case 15:
				return player::bone::left_foot3;
			case 16:
				return player::bone::left_foot4;
			case 17:
				return player::bone::right_foot1;
			case 18:
				return player::bone::right_foot2;
			case 19:
				return player::bone::right_foot3;
			case 20:
				return player::bone::right_foot4;
			default:
				return player::bone::head;
			}
		}
	};
	struct local_player {
		vector3 origin;
	};
	struct game {
		std::array<player_data, 150> players;
		local_player local_player;
		bool valid;
	};
	void update(game& data);
}