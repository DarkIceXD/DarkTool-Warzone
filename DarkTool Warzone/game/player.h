#pragma once
#include <cstdint>
#include "structs.h"

struct player {
	enum class stance
	{
		standing = 0,
		crouching = 1,
		crawling = 2,
		downed = 3,
	};

	enum class bone {
		head = 7,
		neck = 6,
		chest = 5,
		mid = 4,
		tummy = 3,

		right_hand1 = 9,
		right_hand2 = 10,
		right_hand3 = 11,
		right_hand4 = 12,

		left_hand1 = 13,
		left_hand2 = 14,
		left_hand3 = 15,
		left_hand4 = 16,

		left_foot1 = 17,
		left_foot2 = 18,
		left_foot3 = 19,
		left_foot4 = 20,

		right_foot1 = 21,
		right_foot2 = 22,
		right_foot3 = 23,
		right_foot4 = 24,

		count
	};

	static constexpr std::array<std::pair<bone, bone>, 20> bone_connections = { {
		{bone::head, bone::neck},
		{bone::neck, bone::chest},
		{bone::chest, bone::mid},
		{bone::mid, bone::tummy},

		{bone::neck, bone::right_hand1},
		{bone::right_hand1, bone::right_hand2},
		{bone::right_hand2, bone::right_hand3},
		{bone::right_hand3, bone::right_hand4},

		{bone::neck, bone::left_hand1},
		{bone::left_hand1, bone::left_hand2},
		{bone::left_hand2, bone::left_hand3},
		{bone::left_hand3, bone::left_hand4},

		{bone::tummy, bone::left_foot1},
		{bone::left_foot1, bone::left_foot2},
		{bone::left_foot2, bone::left_foot3},
		{bone::left_foot3, bone::left_foot4},

		{bone::tummy, bone::right_foot1},
		{bone::right_foot1, bone::right_foot2},
		{bone::right_foot2, bone::right_foot3},
		{bone::right_foot3, bone::right_foot4}
	} };

	player(const uintptr_t base, const int index);
	[[nodiscard]] bool is_valid() const;
	[[nodiscard]] bool get_origin(vector3& out) const;
	[[nodiscard]] stance get_stance() const;
	[[nodiscard]] int get_team() const;
	[[nodiscard]] name get_name_struct(const uintptr_t name_array_base) const;
	[[nodiscard]] bool is_visible(const uintptr_t visible_base) const;
	[[nodiscard]] static bool get_bounding_box(vector2& min, vector2& max, const std::array<vector3, 21>& bones, const vector3& camera_pos, const ref_def& ref_def);
	[[nodiscard]] static bool get_bounding_box_fallback(vector2& min, vector2& max, const vector3& origin_pos, const stance stance, const vector3& camera_pos, const ref_def& ref_def);
	[[nodiscard]] static float estimate_head_position(const stance stance);
	[[nodiscard]] static float estimate_width(const stance stance);
	[[nodiscard]] static uintptr_t get_name_array_base(const uintptr_t base);
	[[nodiscard]] static bool get_local_index(const uintptr_t client_info, int& out);
	[[nodiscard]] static uintptr_t get_bone_ptr(const uint64_t bone_base, const uint64_t bone_index);
	[[nodiscard]] static vector3 get_bone_base_pos(const uintptr_t client_info);
	[[nodiscard]] static vector3 get_bone_position(const uintptr_t bone_ptr, const vector3& base_pos, const player::bone bone);
	[[nodiscard]] static std::array<vector3, static_cast<size_t>(bone::count)> get_all_bones(const uintptr_t bone_ptr);
	uintptr_t base;
	int index;
};