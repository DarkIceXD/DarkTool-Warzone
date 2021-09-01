#pragma once

namespace offsets {
	constexpr auto refdef = 0x17C29CB0;
	constexpr auto name_array = 0x17C352D8;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x14CA7E70;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x89928;
	constexpr auto local_index_pos = 0x1FC;
	namespace player {
		constexpr auto size = 0x3AD8;
		constexpr auto valid = 0xA8;
		constexpr auto pos = 0x3AC0;
		constexpr auto team = 0x360;
		constexpr auto stance = 0x88C;
		constexpr auto dead_1 = 0x39B4;
		constexpr auto dead_2 = 0x564;
	}
	namespace bone {
		constexpr auto base_pos = 0x4922C;
		constexpr auto index_struct_size = 0x150;
	}
}