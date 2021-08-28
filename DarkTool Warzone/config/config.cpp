#include "config.h"
#include <fstream>

config::config()
{
	std::ifstream stream(conf_name);
	if (stream.good())
	{
		const auto json = nlohmann::json::parse(stream, nullptr, false);
		if (!json.is_discarded())
		{
			esp = json.value<struct esp>("esp", {});
			aimbot = json.value<struct aimbot>("aimbot", {});
		}
	}
}

void config::save() const
{
	nlohmann::json json(*this);
	std::ofstream stream(conf_name);
	stream << json;
}