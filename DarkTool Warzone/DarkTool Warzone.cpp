#include "driver/driver.h"
#include "game/globals.h"
#include "overlay/overlay.hpp"
#include "config/config.h"
#include "utilities/xorstr.h"
#include <iostream>
#include <thread>
#include <mutex>

static std::mutex mtx;
static data::game game_data;

void overlay_execute()
{
	if (!overlay::create_overlay(driver::pid()))
	{
		std::cout << "Cannot create overlay.\n";
		return;
	}
	MSG message;
	do {
		if (PeekMessage(&message, overlay_window::hwnd, 0, 0, PM_REMOVE)) {
			TranslateMessage(&message);
			DispatchMessage(&message);
		}
		HWND ForegroundWindow = GetForegroundWindow();
		if (ForegroundWindow == target::hwnd) {
			HWND TempProcessHwnd = GetWindow(ForegroundWindow, GW_HWNDPREV);
			SetWindowPos(overlay_window::hwnd, TempProcessHwnd, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		}
		{
			std::lock_guard lock(mtx);
			overlay::render(game_data);
		}
		if (GetAsyncKeyState(VK_END) & 1)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	} while (message.message != WM_QUIT);
	overlay::destroy();
}

void collect_data()
{
	globals::base = driver::get_base();
	globals::peb = driver::get_peb();
	std::cout
		<< std::hex
		<< "base: " << globals::base << '\n'
		<< "peb: " << globals::peb << '\n'
		<< std::dec;
	while (true)
	{
		{
			std::lock_guard lock(mtx);
			data::update(game_data);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(40));
	}
}

int main()
{
	const auto driver_status = driver::initialize(xorstr("ModernWarfare.exe"));
	switch (driver_status)
	{
	case driver::status::events_failed:
		std::cout << "Can't create events.\n" << "Press enter to quit.\n";
		std::cin.get();
		return 0;
	case driver::status::process_not_found:
		std::cout << "Can't find process. Did you start the game?\n" << "Press enter to quit.\n";
		std::cin.get();
		return 0;
	case driver::status::driver_connection_failed:
		std::cout << "Can't connect to driver. Did you start the driver?\n" << "Press enter to quit.\n";
		std::cin.get();
		return 0;
	default:
		break;
	}
	std::cout
		<< "Close this to disable DarkTool Overlay\n"
		<< "Press INS to open Menu\n"
		<< "Press END to close (panic button)\n";
	cfg = new config();
	std::thread worker(collect_data);
	worker.detach();
	overlay_execute();
	cfg->save();
	delete cfg;
}