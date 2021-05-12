#pragma once
#include <cstdint>
#include "../math/vector2d.hpp"

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
	vec3_t origin() const;
	character_stance stance() const;
	int team() const;
	void get_bounding_box_fallback(vec2_t& min, vec2_t& max) const;
	float estimate_head_position_from_origin() const;
	int index;
	uintptr_t base;
};