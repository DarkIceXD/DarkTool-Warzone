#include "features.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../math/math.hpp"

void features::aimbot::draw(ImDrawList* d, const ref_def& refdef, const vector3& camera_pos, const vector2& camera_angles)
{
	if (!cfg->aimbot.enabled)
		return;

	if (!GetAsyncKeyState(0x56))
		return;

	auto smallest_fov = FLT_MAX;
	vector2 new_angle{};
	/*for (int i = 0; i < data::players.size(); i++)
	{
		const auto& player = data::players[i];
		if (!player.valid)
			continue;

		const auto current_angle = math::calculate_angle_relative(camera_pos, player.origin, camera_angles);
		const auto fov = math::fov(current_angle);
		if (fov < smallest_fov)
		{
			smallest_fov = fov;
			new_angle = current_angle;
		}
	}
	const auto dx = -new_angle.y;
	const auto dy = new_angle.x;*/
	const vector2 middle(refdef.width / 2, refdef.height / 2);
	for (int i = 0; i < data::players.size(); i++)
	{
		const auto& player = data::players[i];
		if (!player.valid)
			continue;

		vector2 feet;
		if (!math::world_to_screen(player.origin + vector3(0, 0, 50), camera_pos, refdef, feet))
			continue;

		feet -= middle;
		const auto fov = feet.length();
		if (fov < smallest_fov)
		{
			smallest_fov = fov;
			new_angle = feet;
		}
	}
	const auto dx = new_angle.x;
	const auto dy = new_angle.y;
	mouse_event(MOUSEEVENTF_MOVE, dx, dy, 0, 0);
}

void features::aimbot::collect(const uint64_t client_info, const uint64_t client_base)
{
}