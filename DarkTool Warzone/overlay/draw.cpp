#include "overlay.hpp"
#include "../features/features.h"

void overlay::draw(ImDrawList* d)
{
	features::esp(d);
	d->AddRectFilled({ 10,10 }, { 20,20 }, IM_COL32(255, 0, 0, 255));
}