#pragma once
#include "json.hpp"
#include <fstream>

namespace json_utils {
	enum class type {
		JSON,
		MSGPACK
	};
	
	inline nlohmann::json type_to_json(std::ifstream& stream, const type t)
	{
		switch (t)
		{
		case type::JSON:
			return nlohmann::json::parse(stream, nullptr, false);
		case type::MSGPACK:
			return nlohmann::json::from_msgpack(stream, true, false);
		default:
			return {};
		}
	}

	inline nlohmann::json type_to_json(const std::vector<char>& buffer, const type t)
	{
		switch (t)
		{
		case type::JSON:
			return nlohmann::json::parse(buffer, nullptr, false);
		case type::MSGPACK:
			return nlohmann::json::from_msgpack(buffer, true, false);
		default:
			return {};
		}
	}

	template<class T>
	constexpr T load(const nlohmann::json& json)
	{
		if (json.is_discarded())
			return {};

		return json.get<T>();
	}

	template<class T>
	constexpr T load(const char* file_name, const type t)
	{
		std::ifstream stream(file_name, std::ios_base::binary);
		if (!stream.good())
			return {};

		return load<T>(type_to_json(stream, t));
	}

	template<class T>
	constexpr T load(const std::vector<char>& buffer, const type t)
	{
		return load<T>(type_to_json(buffer, t));
	}

	template<class T>
	constexpr void save(const char* file_name,  const type t, const T& value)
	{
		std::ofstream stream(file_name, std::ios_base::binary);
		switch (t)
		{
		case type::JSON:
		{
			const nlohmann::json json(value);
			stream << json;
			break;
		}
		case type::MSGPACK:
		{
			const auto bytes = nlohmann::json::to_msgpack(value);
			stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
			break;
		}
		default:
			break;
		}
	}
}