#include "player.h"
#include "globals.h"
#include "offsets.h"
#include "../driver/driver.h"
#include "../math/math.hpp"

player::player(const uintptr_t base, const int index) : base(base), index(index) {}

bool player::valid() const
{
	const auto valid = driver::read<int>(base + offsets::player::valid);
	if (valid != 1)
		return false;

	const auto dead_1 = driver::read<int>(base + offsets::player::dead_1);
	if (dead_1)
		return false;

	const auto dead_2 = driver::read<int>(base + offsets::player::dead_2);
	if (dead_2)
		return false;

	return true;
}

vector3 player::origin() const
{
	const auto position_address = driver::read<uintptr_t>(base + offsets::player::pos);
	if (position_address == 0 || position_address >= 0xFFFFFFFFFFFFFFF)
		return {};

	return driver::read<vector3>(position_address + 0x40);
}

character_stance player::stance() const
{
	return driver::read<character_stance>(base + offsets::player::stance);
}

int player::team() const
{
	return driver::read<int>(base + offsets::player::team);
}

void player::get_bounding_box_fallback(vector2& min, vector2& max, const vector3& camera_pos, const ref_def& ref_def) const
{
	const auto origin_pos = origin();
	const auto head_pos = origin_pos + vector3(0, 0, estimate_head_position_from_origin());
	vector2 head_pos_screen, feet_pos_screen;
	math::world_to_screen(head_pos + vector3(0, 0, 10), camera_pos, ref_def, head_pos_screen);
	math::world_to_screen(origin_pos, camera_pos, ref_def, feet_pos_screen);
	const auto height = feet_pos_screen.y - head_pos.y;
	const auto width = height / 2;

	constexpr auto size = 1;

	min.x = feet_pos_screen.x - width - size;
	min.y = feet_pos_screen.y + size;
	max.x = feet_pos_screen.x + width + size;
	max.y = head_pos_screen.y - size;
}

float player::estimate_head_position_from_origin() const
{
	switch (stance())
	{
	case character_stance::Crouching:
		return 40;
	case character_stance::Crawling:
		return 10;
	case character_stance::Downed:
		return 20;
	default:
		return 58;
	}
}