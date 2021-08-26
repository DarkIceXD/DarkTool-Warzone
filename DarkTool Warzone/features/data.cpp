#include "data.h"
#include "features.h"
#include "../game/decryption.h"
#include "../game/globals.h"

void data::collect()
{
	const auto client_info = decryption::decrypt_client_info(globals::base, globals::peb);
	if (!client_info)
		return;

	const auto client_base = decryption::decrypt_client_base(client_info, globals::base, globals::peb);
	if (!client_base)
		return;

	features::esp::collect(client_info, client_base);
}