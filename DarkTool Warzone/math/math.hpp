#pragma once
#include "../game/structs.h"
#include "vector2.hpp"

namespace math {
	constexpr float pi = 3.14159265358979323846f;
	constexpr float deg2rad = pi / 180;
	constexpr float rad2deg = 180 / pi;

	[[nodiscard]] uintptr_t get_camera_base(const uintptr_t base) noexcept;
	[[nodiscard]] camera get_camera_struct(const uintptr_t base) noexcept;
	[[nodiscard]] bool world_to_screen(const vector3& world_location, const vector3& camera_position, const int screen_width, const int screen_height, const vector2& field_of_view, const std::array<vector3, 3>& matrices, vector2& out) noexcept;
	[[nodiscard]] bool world_to_screen(const vector3& world_location, const vector3& camera_pos, const ref_def& ref_def, vector2& out) noexcept;
	[[nodiscard]] float units_to_m(const float units) noexcept;
	[[nodiscard]] vector2 calculate_angle(const vector3& src, const vector3& dst) noexcept;
	[[nodiscard]] vector2 calculate_angle_relative(const vector3& src, const vector3& dst, const vector2& angles) noexcept;
	[[nodiscard]] float fov(const vector2& a) noexcept;
}