#include "player.h"
#include "globals.h"
#include "offsets.h"
#include "../driver/driver.h"
#include "../math/math.hpp"
#include <iostream>

player::player(const uintptr_t base, const int index) : base(base), index(index) {}

bool player::valid() const
{
	const auto valid = driver::read<int>(base + offset::character_info::VALID);
	if (valid != 1)
	{
		std::cout << "valid\n";
		return false;
	}

	const auto dead_1 = driver::read<int>(base + offset::character_info::DEAD_1);
	if (dead_1 != 0)
	{
		std::cout << "dead1\n";
		return false;
	}

	const auto dead_2 = driver::read<int>(base + offset::character_info::DEAD_2);
	if (dead_2 != 0)
	{
		std::cout << "dead2\n";
		return false;
	}

	return true;
}

vec3_t player::origin() const
{
	const auto position_address = driver::read<uintptr_t>(base + offset::character_info::POS_PTR);
	if (position_address == 0 || position_address >= 0xFFFFFFFFFFFFFFF)
	{
		std::cout << "position invalid\n";
		return {};
	}

	return driver::read<vec3_t>(position_address + 0x40);
}

character_stance player::stance() const
{
	return driver::read<character_stance>(base + offset::character_info::STANCE);
}

int player::team() const
{
	return driver::read<int>(base + offset::character_info::TEAM);
}

void player::get_bounding_box_fallback(vec2_t& min, vec2_t& max) const
{
	const auto origin_pos = origin();
	const auto head_pos = origin_pos + vec3_t(0, 0, estimate_head_position_from_origin());
	const auto head_pos_screen = math::world_to_screen(head_pos + vec3_t(0, 0, 10));
	const auto feet_pos_screen = math::world_to_screen(origin_pos);

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