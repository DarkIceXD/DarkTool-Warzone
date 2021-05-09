#include "overlay.hpp"

void overlay::draw(ImDrawList* d)
{
	d->AddRectFilled({ 10,10 }, { 20,20 }, IM_COL32(255, 0, 0, 255));
}