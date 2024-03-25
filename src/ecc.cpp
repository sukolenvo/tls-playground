#include <ranges>
#include <utility>

#include "math.hpp"
#include "ecc.hpp"

BigNumber undo_multiplication(const BigNumber &x, const BigNumber &y, const BigNumber &modulus)
{
	const auto inverse = y.inverse_multiplicative(modulus);
	return x * inverse % modulus;
}

BigPoint EllipticCurve::sum_points(const BigPoint &first, const BigPoint &second, const BigNumber &modulus) const
{
	const auto lambda = undo_multiplication(second.y - first.y, second.x - first.x, modulus);

	const auto x = (lambda * lambda - first.x - second.x) % modulus;
	const auto y = (lambda * (first.x - x) - first.y) % modulus;
	return { x, y };
}

BigPoint EllipticCurve::double_point(const BigPoint &point, const BigNumber &modulus) const
{
	const auto lambda = undo_multiplication(
			BigNumber({ 3 }) * point.x * point.x + a,
			BigNumber({ 2 }) * point.y,
			modulus);

	const auto x = (lambda * lambda - BigNumber({ 2 }) * point.x) % modulus;
	const auto y = (lambda * (point.x - x) - point.y) % modulus;
	return { x, y };
}

BigPoint EllipticCurve::multiply_point(const BigPoint &point, const BigNumber &multiplier, const BigNumber &modulus) const
{
	std::optional<BigPoint> accumulator{};
	auto add_operand = point;
	for (auto val: std::ranges::reverse_view(multiplier.data()))
	{
		for (unsigned char mask = 1; mask != 0 && mask <= val; mask <<= 1)
		{
			if ((val & mask) != 0)
			{
				if (accumulator.has_value())
				{
					accumulator = sum_points(accumulator.value(), add_operand, modulus);
				}
				else
				{
					accumulator = add_operand;
				}
			}
			add_operand = double_point(add_operand, modulus);
		}
	}
	return accumulator.value();
}

EllipticCurve::EllipticCurve(BigNumber a, BigNumber b) : a(std::move(a)), b(std::move(b))
{

}

bool operator==(const BigPoint &first, const BigPoint &second)
{
	return first.x == second.x && first.y == second.y;
}