#include "../overlay/overlay.hpp"
#include "features.h"
#include "../math/math.hpp"
#include "../game/decryption.h"
#include "../game/globals.h"
#include "../game/offsets.h"
#include "../driver/driver.h"
#include "../config/config.h"
#include "../utilities/utils.h"

static uintptr_t camera_base = 0;

void overlay::draw(ImDrawList* d)
{
	if (!data::local_player.valid)
		return;

	if (!utils::is_valid_ptr(camera_base))
		return;

	static auto ref_def_ptr = decryption::get_ref_def(globals::base, offsets::refdef);
	if (!utils::is_valid_ptr(ref_def_ptr))
	{
		ref_def_ptr = decryption::get_ref_def(globals::base, offsets::refdef);
		return;
	}

	const auto refdef = driver::read<ref_def>(ref_def_ptr);
	const auto camera = math::get_camera_struct(camera_base);
	features::esp::draw(d, refdef, camera.position);
	features::aimbot::draw(d, refdef, camera.position);
}

void data::collect()
{
	if (!cfg->esp.bind.enabled && !cfg->aimbot.bind.enabled)
		return;

	static auto full_refresh = true;
	static uint64_t client_info = 0;
	static uint64_t client_base = 0;
	static uint64_t bone_base = 0;
	static uint64_t visible_base = 0;
	static uintptr_t name_base = 0;

	const auto client_info_new = decryption::decrypt_client_info(globals::base, globals::peb);
	if (client_info != client_info_new)
		full_refresh = true;

	if (full_refresh)
	{
		client_info = client_info_new;
		if (!utils::is_valid_ptr(client_info))
		{
			data::local_player.valid = false;
			return;
		}

		client_base = decryption::decrypt_client_base(client_info, globals::base, globals::peb);
		if (!utils::is_valid_ptr(client_base))
		{
			data::local_player.valid = false;
			return;
		}

		bone_base = decryption::decrypt_bone_base(globals::base, globals::peb);
		if (!utils::is_valid_ptr(bone_base))
		{
			data::local_player.valid = false;
			return;
		}

		visible_base = decryption::get_visible_base(globals::base, offsets::visible, offsets::distribute);
		if (!utils::is_valid_ptr(visible_base))
		{
			data::local_player.valid = false;
			return;
		}

		name_base = player::get_name_array_base(globals::base);
		if (!utils::is_valid_ptr(name_base))
		{
			data::local_player.valid = false;
			return;
		}

		camera_base = math::get_camera_base(globals::base);
		if (!utils::is_valid_ptr(camera_base))
		{
			data::local_player.valid = false;
			return;
		}
		full_refresh = false;
	}

	const auto local_index = player::get_local_index(client_info);
	if (!local_index)
	{
		data::local_player.valid = false;
		return;
	}

	const player local_player(client_base, *local_index);
	const auto local_origin_opt = local_player.get_origin();
	if (!local_origin_opt)
	{
		data::local_player.valid = false;
		return;
	}
	const auto local_origin = *local_origin_opt;
	const auto local_team = local_player.get_team();
	const auto bone_base_pos = player::get_bone_base_pos(client_info);
	for (int i = 0; i < data::players.size(); i++)
	{
		auto& player_data = data::players[i];
		player_data.valid = false;
		player_data.esp_valid = false;
		player_data.aimbot_valid = false;
		const player p(client_base, i);
		if (!p.is_valid())
			continue;

		if (p.get_team() == local_team)
			continue;

		const auto origin = p.get_origin();
		if (!origin)
			continue;

		player_data.origin = *origin;

		const auto bone_ptr = player::get_bone_ptr(bone_base, decryption::get_bone_index(i, globals::base));
		if (!bone_ptr)
			continue;

		const auto bones = player::get_all_bones(bone_ptr);
		for (size_t j = 0; j < player_data.bones.size(); j++)
			player_data.bones[j] = bone_base_pos + bones[static_cast<size_t>(player_data::index_to_bone(j))];

		player_data.stance = p.get_stance();
		player_data.distance = static_cast<int>(math::units_to_m((player_data.origin - local_origin).length()));
		const auto name = p.get_name_struct(name_base);
		player_data.health = name.health / 127.f;
		strcpy_s(player_data.name, name.name);
		player_data.visible = p.is_visible(visible_base);
		player_data.valid = true;
	}
	data::local_player.valid = true;

	features::esp::collect();
	features::aimbot::collect();
}