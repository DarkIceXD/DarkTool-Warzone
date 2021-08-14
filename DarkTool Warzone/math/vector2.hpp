#pragma once
#include "vector3.hpp"

class vector2 {
public:
	float x, y;
	constexpr vector2(const float _x, const float _y) noexcept : x(_x), y(_y) { }
	constexpr vector2() noexcept : vector2(0, 0) { }
	constexpr vector2(const vector3 vec) noexcept : vector2(vec.x, vec.y) { }
	constexpr vector2& operator+=(const vector2& obj) noexcept
	{
		this->x += obj.x;
		this->y += obj.y;
		return *this;
	}
	constexpr vector2& operator-=(const vector2& obj) noexcept
	{
		this->x -= obj.x;
		this->y -= obj.y;
		return *this;
	}
	constexpr vector2& operator*=(const float c) noexcept
	{
		this->x *= c;
		this->y *= c;
		return *this;
	}
	constexpr vector2& operator/=(const float c) noexcept
	{
		this->x /= c;
		this->y /= c;
		return *this;
	}
	constexpr friend vector2 operator*(vector2 lhs, const float c) noexcept
	{
		lhs *= c;
		return lhs;
	}
	constexpr friend vector2 operator/(vector2 lhs, const float c) noexcept
	{
		lhs /= c;
		return lhs;
	}
	constexpr friend vector2 operator+(vector2 lhs, const vector2& rhs) noexcept
	{
		lhs += rhs;
		return lhs;
	}
	constexpr friend vector2 operator-(vector2 lhs, const vector2& rhs) noexcept
	{
		lhs -= rhs;
		return lhs;
	}
	[[nodiscard]] float length() const noexcept {
		return sqrt((x * x) + (y * y));
	}
};
