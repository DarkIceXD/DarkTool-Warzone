#pragma once

namespace offsets {
	constexpr auto refdef = 0x1796FE20;
	constexpr auto name_array = 0x1797B498;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x15665FF0;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x16650;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A010978;
	constexpr auto visible = 0x63619B0;

	namespace player {
		constexpr auto size = 0x3A90;
		constexpr auto valid = 0x1F8;
		constexpr auto pos = 0x13E8;
		constexpr auto team = 0x84C;
		constexpr auto stance = 0x948;
		constexpr auto dead_1 = 0x3A70;
		constexpr auto dead_2 = 0x178;
	}

	namespace bone {
		constexpr auto base_pos = 0x6E2BC;
		constexpr auto index_struct_size = 0x150;
	}
}