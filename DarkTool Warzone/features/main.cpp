#include "../overlay/overlay.hpp"
#include "features.h"
#include "../math/math.hpp"
#include "../game/decryption.h"
#include "../game/globals.h"
#include "../game/offsets.h"
#include "../driver/driver.h"
#include "../config/config.h"

void overlay::draw(ImDrawList* d)
{
	if (!data::local_player.valid)
		return;

	const auto camera_base = math::get_camera_base(globals::base);
	if (!camera_base)
		return;

	const auto camera = math::get_camera_struct(camera_base);

	const auto ref_def_ptr = decryption::get_ref_def(globals::base, offsets::refdef);
	if (!ref_def_ptr)
		return;

	const auto refdef = driver::read<ref_def>(ref_def_ptr);
	features::esp::draw(d, refdef, camera.position);
	features::aimbot::draw(d, refdef, camera.position);
}
#include <iostream>
void data::collect()
{
	if (!cfg->esp.bind.enabled && !cfg->aimbot.bind.enabled)
		return;

	const auto client_info = decryption::decrypt_client_info(globals::base, globals::peb);
	if (!client_info)
	{
		data::local_player.valid = false;
		return;
	}

	const auto client_base = decryption::decrypt_client_base(client_info, globals::base, globals::peb);
	if (!client_base)
	{
		data::local_player.valid = false;
		return;
	}

	const auto name_base = player::get_name_array_base(globals::base);
	if (!name_base)
	{
		data::local_player.valid = false;
		return;
	}

	static const auto visible_base = decryption::get_visible_base(globals::base, offsets::visible, offsets::distribute);
	if (!visible_base)
	{
		std::cout << "visible_base was null\n";
		data::local_player.valid = false;
		return;
	}

	const auto local_index = player::get_local_index(client_info);
	if (local_index < 0)
	{
		data::local_player.valid = false;
		return;
	}

	const player local_player(client_base, local_index);
	data::local_player.origin = local_player.get_origin();
	const auto local_team = local_player.get_team();
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

		player_data.origin = p.get_origin();
		player_data.stance = p.get_stance();
		player_data.distance = (int)math::units_to_m((player_data.origin - data::local_player.origin).length());
		const auto name = p.get_name_struct(name_base);
		player_data.health = name.health / 127.f;
		strcpy_s(player_data.name, name.name);
		player_data.visible = p.is_visible(visible_base);
		player_data.valid = true;
	}
	data::local_player.valid = true;

	features::esp::collect();
	features::aimbot::collect(client_info);
}