#pragma once
#include <cmath>

class vector3 {
public:
	float x, y, z;
	constexpr vector3(const float x, const float y, const float z) noexcept : x(x), y(y), z(z) {}
	constexpr vector3() noexcept : vector3(0, 0, 0) {}
	[[nodiscard]] constexpr float length_sqr() const noexcept
	{
		return x * x + y * y + z * z;
	}
	[[nodiscard]] float length() const noexcept
	{
		return sqrt(length_sqr());
	}
	constexpr vector3& operator+=(const vector3& obj) noexcept
	{
		this->x += obj.x;
		this->y += obj.y;
		this->z += obj.z;
		return *this;
	}
	constexpr vector3& operator-=(const vector3& obj) noexcept
	{
		this->x -= obj.x;
		this->y -= obj.y;
		this->z -= obj.z;
		return *this;
	}
	constexpr vector3& operator*=(const float c) noexcept
	{
		this->x *= c;
		this->y *= c;
		this->z *= c;
		return *this;
	}
	constexpr vector3& operator/=(const float c) noexcept
	{
		this->x /= c;
		this->y /= c;
		this->z /= c;
		return *this;
	}
	constexpr friend vector3 operator*(vector3 lhs, const float c) noexcept
	{
		lhs *= c;
		return lhs;
	}
	constexpr friend vector3 operator/(vector3 lhs, const float c) noexcept
	{
		lhs /= c;
		return lhs;
	}
	constexpr friend vector3 operator+(vector3 lhs, const vector3& rhs) noexcept
	{
		lhs += rhs;
		return lhs;
	}
	constexpr friend vector3 operator-(vector3 lhs, const vector3& rhs) noexcept
	{
		lhs -= rhs;
		return lhs;
	}
	[[nodiscard]] constexpr friend bool operator!=(const vector3 lhs, const vector3 rhs) noexcept
	{
		return lhs.x != rhs.x || lhs.y != rhs.y || lhs.z != rhs.z;
	}
	[[nodiscard]] constexpr friend bool operator==(const vector3 lhs, const vector3 rhs) noexcept
	{
		return !(lhs != rhs);
	}
	[[nodiscard]] constexpr bool is_zero() const noexcept
	{
		return *this == vector3(0, 0, 0);
	}
	[[nodiscard]] float length_2d() const noexcept
	{
		return sqrt((x * x) + (y * y));
	}
	float normalize() noexcept
	{
		const auto len = length();
		if (len != 0)
			*this /= len;
		return len;
	}
	[[nodiscard]] vector3 normalized() const noexcept
	{
		vector3 vec(*this);
		vec.normalize();
		return vec;
	}
	[[nodiscard]] static constexpr vector3 cross_product(const vector3& v1, const vector3& v2) noexcept
	{
		return { (v1.y * v2.z) - (v1.z * v2.y), (v1.z * v2.x) - (v1.x * v2.z), (v1.x * v2.y) - (v1.y * v2.x) };
	}
	[[nodiscard]] constexpr vector3 cross_product(const vector3& other) const noexcept
	{
		return cross_product(*this, other);
	}
	[[nodiscard]] constexpr float dot(const vector3& other) const noexcept
	{
		return (x * other.x + y * other.y + z * other.z);
	}
	[[nodiscard]] constexpr float dot(const float* other) const noexcept
	{
		return (x * other[0] + y * other[1] + z * other[2]);
	}
};