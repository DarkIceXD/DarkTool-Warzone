#pragma once
#include "../math/vector2.hpp"
#include <array>

struct ref_def_view {
	vector2 tan_half_fov;
	char pad0[0xC];
	std::array<vector3, 3> axis;
};

struct ref_def {
	int x;
	int y;
	int width;
	int height;
	ref_def_view view;
};

struct camera {
	vector3 position;
	vector2 angles;
};

struct name {
	int entity_index;
	char name[0x24];
	char unk1[0x24];
	char unk2[0x40];
	int health;
};