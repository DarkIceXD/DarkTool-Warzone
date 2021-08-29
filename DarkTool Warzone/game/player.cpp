#include "player.h"
#include "offsets.h"
#include "../driver/driver.h"
#include "../math/math.hpp"

player::player(const uintptr_t client_base, const int index) : base(client_base + ((uint64_t)index * offsets::player::size)), index(index) {}

[[nodiscard]] bool player::is_valid() const
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

[[nodiscard]] vector3 player::get_origin() const
{
	const auto position_address = driver::read<uintptr_t>(base + offsets::player::pos);
	if (position_address == 0 || position_address >= 0xFFFFFFFFFFFFFFF)
		return {};

	return driver::read<vector3>(position_address + 0x40);
}

[[nodiscard]] character_stance player::get_stance() const
{
	return driver::read<character_stance>(base + offsets::player::stance);
}

[[nodiscard]] int player::get_team() const
{
	return driver::read<int>(base + offsets::player::team);
}

[[nodiscard]] name player::get_name_struct(const uintptr_t name_array_base) const
{
	return driver::read<name>(name_array_base + offsets::name_array_pos + ((uint64_t)index * 0xD0));
}

[[nodiscard]] bool player::get_bounding_box_fallback(vector2& min, vector2& max, const vector3& origin_pos, const character_stance stance, const vector3& camera_pos, const ref_def& ref_def)
{
	const auto head_pos = origin_pos + vector3(0, 0, estimate_head_position(stance));

	vector2 head_pos_screen, feet_pos_screen;
	if (!math::world_to_screen(head_pos, camera_pos, ref_def, head_pos_screen) ||
		!math::world_to_screen(origin_pos, camera_pos, ref_def, feet_pos_screen))
		return false;

	const auto width = (feet_pos_screen.y - head_pos_screen.y) * estimate_width(stance);
	min = { feet_pos_screen.x - width, feet_pos_screen.y };
	max = { feet_pos_screen.x + width, head_pos_screen.y };

	return true;
}

[[nodiscard]] float player::estimate_head_position(const character_stance stance)
{
	switch (stance)
	{
	case character_stance::crouching:
		return 50;
	case character_stance::crawling:
		return 20;
	case character_stance::downed:
		return 30;
	default:
		return 68;
	}
}

[[nodiscard]] float player::estimate_width(const character_stance stance)
{
	switch (stance)
	{
	case character_stance::crouching:
		return 1 / 2.5f;
	case character_stance::crawling:
		return 2.5f;
	case character_stance::downed:
		return 2.f;
	default:
		return 1 / 4.f;
	}
}

[[nodiscard]] uintptr_t player::get_name_array_base(const uintptr_t base)
{
	return driver::read<uintptr_t>(base + offsets::name_array);
}

[[nodiscard]] int player::get_local_index(const uintptr_t client_info)
{
	const auto local_index = driver::read<uintptr_t>(client_info + offsets::local_index);
	if (!local_index)
		return -1;
	return driver::read<int>(local_index + offsets::local_index_pos);
}

[[nodiscard]] uintptr_t player::get_bone_ptr(const uint64_t bone_base, const uint64_t bone_index)
{
	return driver::read<uintptr_t>(bone_base + (bone_index * offsets::bone::index_struct_size) + 0xC0);
}

[[nodiscard]] vector3 player::get_bone_base_pos(const uintptr_t client_info)
{
	return driver::read<vector3>(client_info + offsets::bone::base_pos);
}

[[nodiscard]] vector3 player::get_bone_position(const uintptr_t bone_ptr, const vector3& base_pos, const int bone)
{
	return base_pos + driver::read<vector3>(bone_ptr + ((uint64_t)bone * 0x20) + 0x10);
}