#pragma once

namespace offsets {
	constexpr auto refdef = 0x18006508;
	constexpr auto name_array = 0x18011D48;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x157D08E0;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x3B058;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A6B4978;
	constexpr auto visible = 0x6300860;

	namespace player {
		constexpr auto size = 0x3AB8;
		constexpr auto valid = 0x294;
		constexpr auto pos = 0x308;
		constexpr auto team = 0x2F0;
		constexpr auto stance = 0x2CF8;
		constexpr auto dead_1 = 0x28CC;
		constexpr auto dead_2 = 0x408;
	}

	namespace bone {
		constexpr auto base_pos = 0x15F84;
		constexpr auto index_struct_size = 0x150;
	}
}