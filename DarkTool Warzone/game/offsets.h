#pragma once

namespace offset {
	constexpr uintptr_t REFDEF = 0x17417598;

	constexpr uintptr_t NAME_ARRAY = 0x1721C5F8;
	constexpr uintptr_t NAME_LIST_OFFSET = 0x4C70;

	constexpr uintptr_t CAMERA_POINTER = 0x146F4700;
	constexpr uintptr_t CAMERA_OFFSET = 0x1D8;

	constexpr uintptr_t LOCAL_INDEX_POINTER = 0x59400;
	constexpr uintptr_t LOCAL_INDEX_OFFSET = 0x1F4;

	namespace character_info {
		constexpr uintptr_t SIZE = 0x3A88;
		constexpr uintptr_t VALID = 0x26D4;
		constexpr uintptr_t POS_PTR = 0x26D8;
		constexpr uintptr_t TEAM = 0x262C;
		constexpr uintptr_t STANCE = 0x2C84;
		constexpr uintptr_t DEAD_1 = 0x10;
		constexpr uintptr_t DEAD_2 = 0x34;
	}

	namespace client_info {
		constexpr uintptr_t ENCRYPTED_PTR = 0x17414C08;
	}

	namespace client_base {
		constexpr uintptr_t BASE_OFFSET = 0x9DC08;
	}
}