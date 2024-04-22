#include <ranges>
#include <utility>

#include "math.hpp"
#include "ecc.hpp"

BigNumber undo_multiplication(const BigNumber &x, const BigNumber &y, const BigNumber &modulus)
{
    const auto inverse = y.inverse_multiplicative(modulus);
    return x * inverse;
}

BigPoint EllipticCurve::sum_points(const BigPoint &first, const BigPoint &second) const
{
    const auto lambda = undo_multiplication(second.y - first.y, second.x - first.x, modulus);

    const auto x = (lambda * lambda - first.x - second.x) % modulus;
    const auto y = (lambda * (first.x - x) - first.y) % modulus;
    return { x, y };
}

BigPoint EllipticCurve::double_point(const BigPoint &point) const
{
    const auto lambda = undo_multiplication(
            BigNumber({ 3 }) * point.x * point.x + a,
            BigNumber({ 2 }) * point.y,
            modulus);

    const auto x = (lambda * lambda - BigNumber({ 2 }) * point.x) % modulus;
    const auto y = (lambda * (point.x - x) - point.y) % modulus;
    return { x, y };
}

BigPoint EllipticCurve::multiply_point(const BigPoint &point, const BigNumber &multiplier) const
{
    std::optional<BigPoint> accumulator{};
    auto add_operand = point;
    const auto data = multiplier.data();
    for (auto i = data.rbegin(); i != data.rend(); ++i)
    {
        for (unsigned char mask = 1; mask != 0; mask <<= 1)
        {
            if ((*i & mask) != 0)
            {
                if (accumulator.has_value())
                {
                    accumulator = sum_points(accumulator.value(), add_operand);
                }
                else
                {
                    accumulator = add_operand;
                }
            }
            add_operand = double_point(add_operand);
        }
    }
    return accumulator.value();
}

EllipticCurve::EllipticCurve(BigNumber a, BigNumber b, BigNumber modulus) : a(std::move(a)),
                                                                            b(std::move(b)),
                                                                            modulus(std::move(modulus))
{

}

bool operator==(const BigPoint &first, const BigPoint &second)
{
    return first.x == second.x && first.y == second.y;
}
