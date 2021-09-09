#pragma once
#include "common.h"
#include <Windows.h>

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

struct keybind {
	bool enabled{ false };
	int type{ 0 };
	int key_bind{ 0 };
	constexpr void run()
	{
		if (type == 1 && GetAsyncKeyState(key_bind) & 1)
			enabled = !enabled;
		else if (type == 2)
			enabled = GetAsyncKeyState(key_bind);
	}
	JSON_SERIALIZE(keybind, enabled, type, key_bind)
};

struct config {
	static constexpr const char* conf_name = "DarkTool Warzone.json";
	config();
	void save() const;
	struct esp {
		keybind bind{};
		int max_distance{ 0 };
		rgb box_color{ 1, 0, 0, 1 };
		rgb box_color_visible{ 0, 1, 0, 1 };
		rgb box_color_downed{ 0, 1, 1, 1 };
		JSON_SERIALIZE(esp, bind, max_distance, box_color, box_color_visible, box_color_downed)
	} esp;
	struct aimbot {
		keybind bind{};
		int max_distance{ 0 };
		float fov{ 5.f };
		int hitbox{ 0 };
		bool visibility_check{ true };
		bool aim_at_downed_players{ false };
		bool show_aim_spot{ true };
		JSON_SERIALIZE(aimbot, bind, max_distance, fov, hitbox, visibility_check, aim_at_downed_players, show_aim_spot)
	} aimbot;
	JSON_SERIALIZE(config, esp, aimbot)
};

inline config* cfg;