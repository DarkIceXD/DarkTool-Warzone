#include "math.hpp"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../game/offsets.h"
#include "../game/structs.h"

vec2_t math::world_to_screen(const vec3_t& world_location, const vec3_t& camera_position, const int screen_width, const int screen_height, const vec2_t& field_of_view, const std::array<vec3_t, 3>& matrices)
{
	const auto local = world_location - camera_position;
	const auto trans = vec3_t(local.dot(matrices[1]), local.dot(matrices[2]), local.dot(matrices[0]));
	if (trans.z < 0.01f)
		return {};

	return { (((float)screen_width / 2) * (1 - (trans.x / field_of_view.x / trans.z))), (((float)screen_height / 2) * (1 - (trans.y / field_of_view.y / trans.z))) };
}

vec2_t math::world_to_screen(const vec3_t& world_location)
{
	const auto refdef_ptr = driver::read<uintptr_t>(globals::pid, globals::base + offset::REFDEF);
	const auto refdef = driver::read<RefDef>(globals::pid, refdef_ptr);
	const auto camera_addr = driver::read<uintptr_t>(globals::pid, globals::base + offset::CAMERA_POINTER);
	if(!camera_addr)
		return {};

	const auto pos = driver::read<vec3_t>(globals::pid, camera_addr + offset::CAMERA_OFFSET);
	return world_to_screen(world_location, pos, refdef.width, refdef.height, refdef.view.tan_half_fov, refdef.view.axis);
}