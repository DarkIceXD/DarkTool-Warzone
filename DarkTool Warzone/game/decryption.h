#pragma once
#include <cstdint>

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb)->uint64_t;
	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb)->uint64_t;
	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb)->uint64_t;
	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase)->uint64_t;
	uintptr_t get_ref_def(const uint64_t imageBase, const uintptr_t ref_def_ptr);
}