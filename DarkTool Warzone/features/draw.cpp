#include "../overlay/overlay.hpp"
#include "features.h"
#include "../math/math.hpp"
#include "../game/globals.h"
#include "../game/decryption.h"
#include "../game/offsets.h"
#include "../driver/driver.h"

void overlay::draw(ImDrawList* d)
{
	if (!data::local_player.valid)
		return;

	const auto camera_base = math::get_camera_base(globals::base);
	if (!camera_base)
		return;

	const auto camera = math::get_camera_struct(camera_base);

	const auto ref_def_ptr = decryption::get_ref_def(globals::base, offsets::refdef);
	if (!ref_def_ptr)
		return;

	const auto refdef = driver::read<ref_def>(ref_def_ptr);
	features::esp::draw(d, refdef, camera.position);
	features::aimbot::draw(d, refdef, camera.position);
}