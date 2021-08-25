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
	bool valid() const;
	vector3 origin() const;
	character_stance stance() const;
	int team() const;
	bool get_bounding_box_fallback(vector2& min, vector2& max, const vector3& origin_pos, const vector3& camera_pos, const ref_def& ref_def) const;
	float estimate_head_position(const character_stance stance) const;
	float estimate_width(const character_stance stance) const;
	int index;
	uintptr_t base;
};