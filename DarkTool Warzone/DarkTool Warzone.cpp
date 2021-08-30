#include "driver/driver.h"
#include "game/globals.h"
#include "overlay/overlay.hpp"
#include "game/data.h"
#include "config/config.h"
#include <iostream>
#include <thread>

void overlay_execute()
{
	if (!overlay::create_overlay(driver::pid()))
	{
		std::cout << "Cannot create overlay.\n";
		return;
	}

	MSG message;
	do
	{
		if (PeekMessageW(&message, overlay::overlay_window, 0, 0, PM_REMOVE)) {
			TranslateMessage(&message);
			DispatchMessageW(&message);
		}

		if (overlay::begin()) {
			overlay::present();
			overlay::end();
		}

		if (GetAsyncKeyState(VK_END) & 1)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	} while (message.message != WM_QUIT);
}

void collect_data()
{
	globals::base = driver::get_process_base_address();
	globals::peb = driver::get_peb();
	std::cout << "base: " << std::hex << globals::base << '\n';
	std::cout << "peb: " << std::hex << globals::peb << '\n';
	while (true)
	{
		data::collect();
		std::this_thread::sleep_for(std::chrono::milliseconds(40));
	}
}

int main()
{
	driver::initialize(L"ModernWarfare.exe");
	if (!driver::connect())
	{
		std::cout << "Cannot connect to driver. Did you start the driver?\n";
		return 0;
	}
	driver::clean_piddbcachetable();
	driver::clean_mmunloadeddrivers();
	std::cout
		<< "Close this to disable DarkTool Overlay\n"
		<< "Press INS to open Menu\n"
		<< "Press END to close (panic button)\n";
	cfg = new config();
	std::thread worker(collect_data);
	worker.detach();
	overlay_execute();
	cfg->save();
}