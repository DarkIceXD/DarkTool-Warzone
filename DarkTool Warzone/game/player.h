#pragma once
#include <cstdint>
#include "structs.h"

enum class character_stance
{
	Standing = 0,
	Crouching = 1,
	Crawling = 2,
	Downed = 3,
};

struct player {
	player(const uintptr_t base, const int index);
	[[nodiscard]] bool valid() const;
	[[nodiscard]] vector3 origin() const;
	[[nodiscard]] character_stance stance() const;
	[[nodiscard]] int team() const;
	[[nodiscard]] bool get_bounding_box_fallback(vector2& min, vector2& max, const vector3& origin_pos, const vector3& camera_pos, const ref_def& ref_def) const;
	[[nodiscard]] float estimate_head_position(const character_stance stance) const;
	[[nodiscard]] float estimate_width(const character_stance stance) const;
	[[nodiscard]] name get_name_struct(const uintptr_t name_array_base) const;
	[[nodiscard]] static uintptr_t get_name_array_base(const uintptr_t base);
	[[nodiscard]] static int get_local_index(const uintptr_t client_info);
	uintptr_t base;
	int index;
};