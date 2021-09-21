#include "math.hpp"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../game/offsets.h"

[[nodiscard]] uintptr_t math::get_camera_base(const uintptr_t base) noexcept
{
	return driver::read<uintptr_t>(base + offsets::camera_base);
}

[[nodiscard]] camera math::get_camera_struct(const uintptr_t base) noexcept
{
	return driver::read<camera>(base + offsets::camera_pos);
}

[[nodiscard]] bool math::world_to_screen(const vector3& world_location, const vector3& camera_position, const int screen_width, const int screen_height, const vector2& field_of_view, const std::array<vector3, 3>& matrices, vector2& out) noexcept
{
	const auto local = world_location - camera_position;
	const auto trans = vector3(local.dot(matrices[1]), local.dot(matrices[2]), local.dot(matrices[0]));
	if (trans.z < 0.01f)
		return false;

	out = { (((float)screen_width / 2) * (1 - (trans.x / field_of_view.x / trans.z))), (((float)screen_height / 2) * (1 - (trans.y / field_of_view.y / trans.z))) };
	if (out.x < 1 || out.y < 1 || (out.x > screen_width) || (out.y > screen_height))
		return false;

	return true;
}

[[nodiscard]] bool math::world_to_screen(const vector3& world_location, const vector3& camera_pos, const ref_def& ref_def, vector2& out) noexcept
{
	return world_to_screen(world_location, camera_pos, ref_def.width, ref_def.height, ref_def.view.tan_half_fov, ref_def.view.axis, out);
}

[[nodiscard]] float math::units_to_m(const float units) noexcept
{
	return units * 0.0254f;
}

[[nodiscard]] float math::pixels_to_fov(const float radius, const float tan_half_fov, const float half_screen_width)
{
	return atan(radius * tan_half_fov / half_screen_width) * 2 * rad2deg;
}
