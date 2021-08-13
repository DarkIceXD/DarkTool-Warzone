#pragma once
#include "../math/vector2d.hpp"
#include <array>

struct ref_def_view {
	vec2_t tan_half_fov;
	char pad0[0xC];
	std::array<vec3_t, 3> axis;
};

struct ref_def {
	int x;
	int y;
	int width;
	int height;
	ref_def_view view;
};

struct Name
{
	int entity_index;
	char name[0x24];
	char unk1[0x24];
	char unk2[0x40];
	int health;
};