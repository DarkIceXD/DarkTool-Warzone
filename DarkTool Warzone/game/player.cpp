#include "player.h"
#include "offsets.h"
#include "../utilities/utils.h"
#include "../driver/driver.h"
#include "../math/math.hpp"
#define BYTEn(x, n)	(*((uint8_t*)&(x)+(n)))
#define BYTE1(x)	BYTEn(x, 1)

player::player(const uintptr_t client_base, const int index) : base(client_base + (static_cast<uint64_t>(index) * offsets::player::size)), index(index) {}

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

[[nodiscard]] bool player::get_origin(vector3& out) const
{
	const auto position_address = driver::read<uintptr_t>(base + offsets::player::pos);
	if (!utils::is_valid_ptr(position_address))
		return false;

	out = driver::read<vector3>(position_address + 0x40);
	return true;
}

[[nodiscard]] player::stance player::get_stance() const
{
	return driver::read<player::stance>(base + offsets::player::stance);
}

[[nodiscard]] int player::get_team() const
{
	return driver::read<int>(base + offsets::player::team);
}

[[nodiscard]] name player::get_name_struct(const uintptr_t name_array_base) const
{
	return driver::read<name>(name_array_base + offsets::name_array_pos + (static_cast<uint64_t>(index) * 0xD0));
}

[[nodiscard]] bool player::is_visible(const uintptr_t visible_base) const
{
	const auto rdx = visible_base + (static_cast<int64_t>(index) * 9 + 0x14E) * 8;
	if (!rdx)
		return false;

	const DWORD visible_flags = (rdx + 0x10) ^ driver::read<DWORD>(rdx + 0x14);
	if (!visible_flags)
		return false;

	const DWORD v511 = visible_flags * (visible_flags + 2);
	if (!v511)
		return false;

	const BYTE visible_flags_1 = driver::read<DWORD>(rdx + 0x10) ^ v511 ^ BYTE1(v511);
	return visible_flags_1 == 3;
}

[[nodiscard]] bool player::get_bounding_box_fallback(vector2& min, vector2& max, const vector3& origin_pos, const player::stance stance, const vector3& camera_pos, const ref_def& ref_def)
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

[[nodiscard]] float player::estimate_head_position(const player::stance stance)
{
	switch (stance)
	{
	case player::stance::crouching:
		return 50;
	case player::stance::crawling:
		return 20;
	case player::stance::downed:
		return 30;
	default:
		return 68;
	}
}

[[nodiscard]] float player::estimate_width(const player::stance stance)
{
	switch (stance)
	{
	case player::stance::crouching:
		return 1 / 2.5f;
	case player::stance::crawling:
		return 2.5f;
	case player::stance::downed:
		return 2.f;
	default:
		return 1 / 4.f;
	}
}

[[nodiscard]] uintptr_t player::get_name_array_base(const uintptr_t base)
{
	return driver::read<uintptr_t>(base + offsets::name_array);
}

[[nodiscard]] bool player::get_local_index(const uintptr_t client_info, int& out)
{
	const auto local_index = driver::read<uintptr_t>(client_info + offsets::local_index);
	if (!utils::is_valid_ptr(local_index))
		return false;

	out = driver::read<int>(local_index + offsets::local_index_pos);
	return true;
}

[[nodiscard]] uintptr_t player::get_bone_ptr(const uint64_t bone_base, const uint64_t bone_index)
{
	return driver::read<uintptr_t>(bone_base + (bone_index * offsets::bone::index_struct_size) + 0xC0);
}

[[nodiscard]] vector3 player::get_bone_base_pos(const uintptr_t client_info)
{
	return driver::read<vector3>(client_info + offsets::bone::base_pos);
}

[[nodiscard]] vector3 player::get_bone_position(const uintptr_t bone_ptr, const vector3& base_pos, const player::bone bone)
{
	return base_pos + driver::read<vector3>(bone_ptr + (static_cast<uint64_t>(bone) * 0x20) + 0x10);
}

std::array<vector3, static_cast<size_t>(player::bone::count)> player::get_all_bones(const uintptr_t bone_ptr)
{
	struct bone {
		vector3 position;
		uint8_t pad0[20];
	};
	const auto raw_bones = driver::read<std::array<bone, static_cast<size_t>(player::bone::count)>>(bone_ptr + 0x10);
	std::array<vector3, raw_bones.size()> bones;
	for (size_t i = 0; i < raw_bones.size(); i++)
		bones[i] = raw_bones[i].position;
	return bones;
}