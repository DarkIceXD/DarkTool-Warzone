#pragma once
#include "common.h"

struct rgb {
	float r{ 1 }, g{ 1 }, b{ 1 }, a{ 1 };
	bool enabled{ false };
	constexpr static rgb scale(const rgb& base, const rgb& end, const float c) noexcept
	{
		constexpr auto scale = [](const float max, const float min, const float scale) { return min + (max - min) * scale; };
		return {
			scale(base.r, end.r, c),
			scale(base.g, end.g, c),
			scale(base.b, end.b, c),
			scale(base.a, end.a, c),
			true
		};
	}
	constexpr uint32_t to_u32() const noexcept
	{
		return ((uint32_t)(r * 255) << 0) | ((uint32_t)(g * 255) << 8) | ((uint32_t)(b * 255) << 16) | ((uint32_t)(a * 255) << 24);
	}
	constexpr void rainbow(const float step) noexcept
	{
		if (r > 0 && b == 0)
		{
			r = (std::max)(r - step, 0.f);
			g = (std::min)(g + step, 1.f);
		}
		else if (g > 0 && r == 0)
		{
			g = (std::max)(g - step, 0.f);
			b = (std::min)(b + step, 1.f);
		}
		else if (b > 0 && g == 0)
		{
			r = (std::min)(r + step, 1.f);
			b = (std::max)(b - step, 0.f);
		}
		else
		{
			r = 1;
			g = 0;
			b = 0;
		}
	}
	JSON_SERIALIZE(rgb, r, g, b, a, enabled)
};

struct config {
	static constexpr const char* conf_name = "DarkTool Warzone.json";
	config();
	void save() const;
	struct esp {
		bool enabled{ true };
		int max_distance{ 0 };
		rgb box_color{ 1, 0, 0, 1 };
		JSON_SERIALIZE(esp, enabled, max_distance, box_color)
	} esp;
	JSON_SERIALIZE(config, esp)
};

inline config* cfg;