#pragma once
#include <array>
#include "vector2d.hpp"

namespace math {
	vec2_t world_to_screen(const vec3_t& world_location, const vec3_t& camera_position, const int screen_width, const int screen_height, const vec2_t& field_of_view, const std::array<vec3_t, 3>& matrices);
	vec2_t world_to_screen(const vec3_t& world_location);
}