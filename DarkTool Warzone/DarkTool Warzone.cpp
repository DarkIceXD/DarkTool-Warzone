#include "driver/driver.h"
#include "game/globals.h"
#include "overlay/overlay.hpp"
#include <iostream>
#include <thread>

void overlay_execute() {
	if (!overlay::create_overlay(driver::pid()))
		return;

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

		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	} while (message.message != WM_QUIT);

	return;
}

int main(int argc, char* argv[]) {
	driver::initialize(L"ModernWarfare.exe");
	driver::connect();
	driver::clean_piddbcachetable();
	driver::clean_mmunloadeddrivers();
	globals::base = driver::get_process_base_address();
	globals::peb = driver::get_peb();
	std::cout << "base: " << globals::base << '\n';
	std::cout << "peb: " << globals::peb << '\n';
	std::cout << "Close this to disable DarkTool Overlay\n";
	std::thread overlay_thread(overlay_execute);
	overlay_thread.join();
	return 0;
}