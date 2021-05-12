#pragma once

namespace offset {
	constexpr auto REFDEF = 0x17211518;

	constexpr auto NAME_ARRAY = 0x1721C5F8;
	constexpr auto NAME_LIST_OFFSET = 0x4C70;

	constexpr auto CAMERA_POINTER = 0x144EE700;
	constexpr auto CAMERA_OFFSET = 0x1D8;

	constexpr auto LOCAL_INDEX_POINTER = 0x59400;
	constexpr auto LOCAL_INDEX_OFFSET = 0x1F4;

	namespace character_info {
		constexpr auto SIZE = 0x3A88;
		constexpr auto VALID = 0x3E4;
		constexpr auto POS_PTR = 0x4C8;
		constexpr auto TEAM = 0xB14;
		constexpr auto STANCE = 0xC00;
		constexpr auto DEAD_1 = 0x14B8;
		constexpr auto DEAD_2 = 0x9B0;
	}

	namespace client_info {
		constexpr auto ENCRYPTED_PTR = 0x1720EB88;
	}

	namespace client_base {
		constexpr auto BASE_OFFSET = 0x9DBE8;
	}
}