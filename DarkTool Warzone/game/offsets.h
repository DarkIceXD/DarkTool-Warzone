#pragma once

namespace offsets {
	constexpr auto refdef = 0x1EB6A2A0;
	constexpr auto name_array = 0x1EB76030;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x1B4D5910;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x20998;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x2123F2F8;
	constexpr auto visible = 0x62A9E20;

	namespace player {
		constexpr auto size = 0x5EE0;
		constexpr auto valid = 0x5FC;
		constexpr auto pos = 0x100;
		constexpr auto team = 0x114;
		constexpr auto stance = 0x53FC;
		constexpr auto dead_1 = 0x294;
		constexpr auto dead_2 = 0x364;
	}

	namespace bone {
		constexpr auto base_pos = 0x21334;
		constexpr auto index_struct_size = 0x150;
	}
}