#pragma once
#include "vector3d.hpp"

class vec2_t {
public:
	float x, y;
	constexpr vec2_t(const float _x, const float _y) noexcept : x(_x), y(_y) { }
	constexpr vec2_t() noexcept : vec2_t(0, 0) { }
	vec2_t(const vec3_t vec) noexcept : vec2_t(vec.x, vec.y) { }
	constexpr vec2_t& operator+=(const vec2_t& obj) noexcept
	{
		this->x += obj.x;
		this->y += obj.y;
		return *this;
	}
	constexpr vec2_t& operator-=(const vec2_t& obj) noexcept
	{
		this->x -= obj.x;
		this->y -= obj.y;
		return *this;
	}
	constexpr vec2_t& operator*=(const float c) noexcept
	{
		this->x *= c;
		this->y *= c;
		return *this;
	}
	constexpr vec2_t& operator/=(const float c) noexcept
	{
		this->x /= c;
		this->y /= c;
		return *this;
	}
	constexpr friend vec2_t operator*(vec2_t lhs, const float c) noexcept
	{
		lhs *= c;
		return lhs;
	}
	constexpr friend vec2_t operator/(vec2_t lhs, const float c) noexcept
	{
		lhs /= c;
		return lhs;
	}
	constexpr friend vec2_t operator+(vec2_t lhs, const vec2_t& rhs) noexcept
	{
		lhs += rhs;
		return lhs;
	}
	constexpr friend vec2_t operator-(vec2_t lhs, const vec2_t& rhs) noexcept
	{
		lhs -= rhs;
		return lhs;
	}
	float length() const noexcept {
		return sqrt((x * x) + (y * y));
	}
};
