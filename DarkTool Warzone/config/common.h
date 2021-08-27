#pragma once
#include "json.hpp"

#define JSON_FROM(v1) \
	if(nlohmann_json_j.contains(#v1)) \
		nlohmann_json_j.at(#v1).get_to(nlohmann_json_t.v1); \

#define JSON_SERIALIZE(Type, ...)  \
    friend void to_json(nlohmann::json& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) } \
    friend void from_json(const nlohmann::json& nlohmann_json_j, Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(JSON_FROM, __VA_ARGS__)) }