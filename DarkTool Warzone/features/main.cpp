#include "../overlay/overlay.hpp"
#include "features.h"
#include "../math/math.hpp"
#include "../game/decryption.h"
#include "../game/offsets.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../utilities/utils.h"

static uintptr_t camera_base = 0;

void overlay::draw(data::game& data, ImDrawList* d)
{
	if (!data.valid)
		return;

	if (!utils::is_valid_ptr(camera_base))
		return;

	static auto ref_def_ptr = decryption::get_ref_def(data.base, offsets::refdef);
	if (!utils::is_valid_ptr(ref_def_ptr))
	{
		ref_def_ptr = decryption::get_ref_def(data.base, offsets::refdef);
		return;
	}

	const auto refdef = driver::read<ref_def>(ref_def_ptr);
	const auto camera = math::get_camera_struct(camera_base);
	for (auto& player : data.players)
	{
		if (!player.valid)
			break;

		if (cfg->esp.max_distance && player.distance > cfg->esp.max_distance &&
			cfg->aimbot.max_distance && player.distance > cfg->aimbot.max_distance)
			break;

		if (player.team == data.local_player.team)
			continue;

		for (size_t i = 0; i < player.bones.size(); i++)
		{
			const auto& bone = player.bones[i];
			auto& screen = player.bones_screen[i];
			screen.valid = false;

			if ((bone - player.origin).length() > 150)
				continue;

			if (!math::world_to_screen(bone, camera.position, refdef, screen.screen))
				continue;

			screen.valid = true;
		}
	}
	features::esp(data, d, refdef, camera);
	features::aimbot(data, d, refdef, camera);
}

void data::update(data::game& data)
{
	data.valid = false;
	if (!cfg->esp.bind.enabled && !cfg->aimbot.bind.enabled)
		return;

	static auto full_refresh = true;
	static uint64_t client_info = 0;
	static uint64_t client_base = 0;
	static uint64_t bone_base = 0;
	static uint64_t visible_base = 0;
	static uint64_t visible_list_old = 0;
	static uintptr_t name_base = 0;

	const auto client_info_new = decryption::decrypt_client_info(data.base, data.peb);
	if (client_info != client_info_new)
		full_refresh = true;

	if (full_refresh)
	{
		client_info = client_info_new;
		if (!utils::is_valid_ptr(client_info))
			return;

		client_base = decryption::decrypt_client_base(client_info, data.base, data.peb);
		if (!utils::is_valid_ptr(client_base))
			return;

		bone_base = decryption::decrypt_bone_base(data.base, data.peb);
		if (!utils::is_valid_ptr(bone_base))
			return;

		name_base = player::get_name_array_base(data.base);
		if (!utils::is_valid_ptr(name_base))
			return;

		camera_base = math::get_camera_base(data.base);
		if (!utils::is_valid_ptr(camera_base))
			return;

		full_refresh = false;
	}

	int local_index;
	if (!player::get_local_index(client_info, local_index))
		return;

	const player local_player(client_base, local_index);
	vector3 local_origin;
	if (!local_player.get_origin(local_origin))
		return;

	data.local_player.team = local_player.get_team();
	const auto bone_base_pos = player::get_bone_base_pos(client_info);
	if (!utils::is_valid_ptr(visible_base))
	{
		visible_base = decryption::get_visible_base(data.base, offsets::visible, offsets::distribute);
		return;
	}
	auto visible_list = driver::read<uint64_t>(visible_base);
	if (!utils::is_valid_ptr(visible_list) || visible_list != visible_list_old)
	{
		visible_base = decryption::get_visible_base(data.base, offsets::visible, offsets::distribute);
		visible_list = driver::read<uint64_t>(visible_base);
	}
	visible_list_old = visible_list;
	for (int i = 0; i < data.players.size(); i++)
	{
		auto& player_data = data.players[i];
		player_data.valid = false;
		const player p(client_base, i);
		if (p.index == local_player.index)
			continue;

		if (!p.is_valid())
			continue;

		if (!p.get_origin(player_data.origin))
			continue;

		const auto bone_ptr = player::get_bone_ptr(bone_base, decryption::get_bone_index(i, data.base));
		if (!bone_ptr)
			continue;

		player_data.delta = player_data.origin - local_origin;
		player_data.distance = static_cast<int>(math::units_to_m(player_data.delta.length()));
		player_data.stance = p.get_stance();
		player_data.team = p.get_team();
		const auto name = p.get_name_struct(name_base);
		player_data.health = name.health / 127.f;
		strcpy_s(player_data.name, name.name);
		player_data.visible = p.is_visible(visible_list);
		const auto bones = player::get_all_bones(bone_ptr);
		for (size_t j = 0; j < player_data.bones.size(); j++)
			player_data.bones[j] = bone_base_pos + bones[static_cast<size_t>(player_data::index_to_bone(j))];
		player_data.valid = true;
	}

	std::sort(data.players.begin(), data.players.end(), [](const auto& a, const auto& b) {
		if (a.valid)
			if (b.valid)
				return a.distance < b.distance;
			else
				return true;
		return false;
		});
	data.valid = true;
}