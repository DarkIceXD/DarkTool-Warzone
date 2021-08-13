#pragma once
#include <cstdint>

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb)->uint64_t;
	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb)->uint64_t;
	uintptr_t get_ref_def(const uintptr_t ref_def_ptr);
}