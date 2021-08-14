#pragma once
#include <array>
#include "../game/structs.h"
#include "vector2.hpp"

namespace math {
	[[nodiscard]] vector3 get_camera_position() noexcept;
	[[nodiscard]] bool world_to_screen(const vector3& world_location, const vector3& camera_position, const int screen_width, const int screen_height, const vector2& field_of_view, const std::array<vector3, 3>& matrices, vector2& out) noexcept;
	[[nodiscard]] bool world_to_screen(const vector3& world_location, const vector3& camera_pos, const ref_def& ref_def, vector2& out) noexcept;
	[[nodiscard]] float units_to_m(const float units) noexcept;
}