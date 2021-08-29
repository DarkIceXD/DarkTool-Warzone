#include "data.h"
#include "features.h"
#include "../game/decryption.h"
#include "../game/globals.h"
#include "../math/math.hpp"
#include "../config/config.h"

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

	const auto local_index = player::get_local_index(client_info);
	if (local_index < 0)
	{
		data::local_player.valid = false;
		return;
	}

	const player local_player(client_base, local_index);
	data::local_player.origin = local_player.get_origin();
	const auto local_team = local_player.get_team();
	for (int i = 0; i < 150; i++)
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
		player_data.valid = true;
	}
	data::local_player.valid = true;

	features::esp::collect();
	features::aimbot::collect(client_info);
}