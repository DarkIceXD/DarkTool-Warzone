#pragma once

namespace offsets {
	constexpr auto refdef = 0x179CFC30;
	constexpr auto name_array = 0x179DB258;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x14A4DE70;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x8E640;
	constexpr auto local_index_pos = 0x1FC;
	namespace player {
		constexpr auto size = 0x3AB8;
		constexpr auto valid = 0x2F00;
		constexpr auto pos = 0x2B18;
		constexpr auto team = 0x2B00;
		constexpr auto stance = 0x3300;
		constexpr auto dead_1 = 0x2C88;
		constexpr auto dead_2 = 0x2F40;
	}
	namespace bone {
		constexpr auto base_pos = 0x4FA3C;
		constexpr auto index_struct_size = 0x150;
	}
}