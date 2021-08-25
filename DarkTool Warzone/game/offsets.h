#pragma once

namespace offsets {
	constexpr auto ref_def = 0x17CADC30;
	constexpr auto camera_base = 0x14D2BE70;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x6E10;
	constexpr auto local_index_pos = 0x1FC;
	namespace player {
		constexpr auto size = 0x3AC8;
		constexpr auto valid = 0x684;
		constexpr auto pos = 0x8B0;
		constexpr auto team = 0x1258;
		constexpr auto stance = 0x944;
		constexpr auto dead_1 = 0x67C;
		constexpr auto dead_2 = 0x1178;
	}
}