#pragma once
#include <cstdint>

namespace decryption
{
	uint64_t client_info(const uint64_t encrypted_address, const uint64_t peb);
	uint64_t client_base(const uint64_t encrypted_address, const uint64_t peb);
}