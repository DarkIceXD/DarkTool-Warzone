#pragma once
#include "../math/vector2d.hpp"

struct RefdefView {
	vec2_t tan_half_fov;
	char unk6[0xC];
	std::array<vec3_t, 3> axis;
};

struct RefDef {
	int x;
	int y;
	int width;
	int height;
	RefdefView view;
};

struct Name
{
	int entity_index;
	char name[0x24];
	char unk1[0x24];
	char unk2[0x40];
	int health;
};