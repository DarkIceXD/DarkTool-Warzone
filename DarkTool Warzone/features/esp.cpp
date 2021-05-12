#include "features.h"
#include "../driver/driver.h"
#include "../game/globals.h"
#include "../game/offsets.h"
#include "../game/decryption.h"
#include "../game/player.h"

static uintptr_t get_client_info_address()
{
	const auto encrypted = driver::read<uintptr_t>(globals::pid, globals::base + offset::client_info::ENCRYPTED_PTR);
	if (!encrypted)
		return 0;

	return decryption::client_info(encrypted, driver::get_peb(globals::pid));
}

static uintptr_t get_client_base_address(const uintptr_t client_info_address) {
	const auto  encrypted_address = driver::read<uintptr_t>(globals::pid, client_info_address + offset::client_base::BASE_OFFSET);
	if (!encrypted_address)
		return 0;
	
	return decryption::client_base(encrypted_address, driver::get_peb(globals::pid));
}

void features::esp(ImDrawList* d)
{
	globals::base = driver::get_process_base_address(globals::pid);
	const auto client_info = get_client_info_address();
	if (!client_info)
		return;

	const auto client_base = get_client_base_address(client_info);
	if (!client_base)
		return;

	for (int i = 0; i < 155; i++)
	{
		player p(client_base + (i * offset::character_info::SIZE), i);
		if (!p.valid())
			continue;

		vec2_t min, max;
		p.get_bounding_box_fallback(min, max);
		d->AddRect({ min.x, min.y }, { max.x, max.y }, IM_COL32_WHITE);
	}
}