#pragma once

namespace offsets {
	constexpr auto refdef = 0x18041338;
	constexpr auto name_array = 0x1804CB78;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x1580B660;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x97418;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A6EF978;
	constexpr auto visible = 0x637FB40;

	namespace player {
		constexpr auto size = 0x3AB8;
		constexpr auto valid = 0x28C;
		constexpr auto pos = 0x290;
		constexpr auto team = 0x298;
		constexpr auto stance = 0xC84;
		constexpr auto dead_1 = 0x6A4;
		constexpr auto dead_2 = 0xBEC;
	}

	namespace bone {
		constexpr auto base_pos = 0x2277C;
		constexpr auto index_struct_size = 0x150;
	}
}