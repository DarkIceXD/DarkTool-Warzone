#pragma once
#include <array>
#include "../game/structs.h"
#include "vector2d.hpp"

namespace math {
	[[nodiscard]] vec3_t get_camera_position() noexcept;
	[[nodiscard]] bool world_to_screen(const vec3_t& world_location, const vec3_t& camera_position, const int screen_width, const int screen_height, const vec2_t& field_of_view, const std::array<vec3_t, 3>& matrices, vec2_t& out) noexcept;
	[[nodiscard]] bool world_to_screen(const vec3_t& world_location, const vec3_t& camera_pos, const ref_def& ref_def, vec2_t& out) noexcept;
	[[nodiscard]] float units_to_m(const float units) noexcept;
}