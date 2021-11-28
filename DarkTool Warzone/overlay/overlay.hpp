#pragma once
#include "../imgui/imgui.h"
#include "../game/data.h"
#include <windows.h>
#include <cstdint>

namespace overlay {
	inline HWND overlay_window;
	bool create_overlay(const uint32_t pid);
	bool begin();
	void present(const data::game& data);
	void draw(const data::game& data, ImDrawList* d);
	void menu();
	void end();
}