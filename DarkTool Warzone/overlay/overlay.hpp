#pragma once
#include "../imgui/imgui.h"
#include <windows.h>
#include <cstdint>

namespace overlay {
	inline HWND overlay_window;
	bool create_overlay(const uint32_t pid);
	bool begin();
	void present();
	void draw(ImDrawList* d);
	void menu();
	void end();
}