#pragma once

namespace offsets {
	constexpr auto refdef = 0x16ECA570;
	constexpr auto name_array = 0x16ED5BE8;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x14BC0760;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x270;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1956A978;
	constexpr auto visible = 0x58C61E0;

	namespace player {
		constexpr auto size = 0x3AB0;
		constexpr auto valid = 0x125C;
		constexpr auto pos = 0x40;
		constexpr auto team = 0x328;
		constexpr auto stance = 0x618;
		constexpr auto dead_1 = 0x370;
		constexpr auto dead_2 = 0x4F8;
	}

	namespace bone {
		constexpr auto base_pos = 0xE1C;
		constexpr auto index_struct_size = 0x150;
	}
}