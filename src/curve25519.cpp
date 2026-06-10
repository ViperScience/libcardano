// Copyright (c) 2026 Viper Science LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Standard Library Includes
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>

// Public libcardano headers
#include <cardano/curve25519.hpp>

// Third-Party Library Headers
#include <sodium.h>

namespace  // anonymous namespace
{

/// @brief Ensure libsodium is initialized exactly once before first use.
/// `sodium_init()` is idempotent and returns 1 if already initialized.
auto ensureInit() -> void
{
    static const int status = sodium_init();
    if (status < 0)
    {
        throw std::runtime_error("Failed to initialize libsodium.");
    }
}

}  // anonymous namespace

namespace cardano::tss::ed25519
{

auto Scalar::reduce(std::span<const uint8_t, 32> in) -> Scalar
{
    ensureInit();
    // crypto_core_ed25519_scalar_reduce consumes a 64-byte value; zero-extend
    // the 32-byte input into the low half before reducing.
    auto wide =
        std::array<uint8_t, crypto_core_ed25519_NONREDUCEDSCALARBYTES>{};
    std::copy_n(in.data(), 32, wide.begin());
    auto out = Scalar{};
    crypto_core_ed25519_scalar_reduce(out.bytes_.data(), wide.data());
    return out;
}  // Scalar::reduce (32-byte)

auto Scalar::reduce(std::span<const uint8_t, 64> in) -> Scalar
{
    ensureInit();
    static_assert(crypto_core_ed25519_NONREDUCEDSCALARBYTES == 64);
    auto out = Scalar{};
    crypto_core_ed25519_scalar_reduce(out.bytes_.data(), in.data());
    return out;
}  // Scalar::reduce (64-byte)

auto Scalar::random() -> Scalar
{
    ensureInit();
    auto out = Scalar{};
    // Uniform, non-zero, canonical scalar via libsodium's CSPRNG.
    crypto_core_ed25519_scalar_random(out.bytes_.data());
    return out;
}  // Scalar::random

auto Scalar::fromUint(uint64_t v) -> Scalar
{
    // v < 2^64 < ℓ, so the little-endian encoding is already canonical.
    auto out = Scalar{};
    for (size_t i = 0; i < 8; ++i)
    {
        out.bytes_[i] = static_cast<uint8_t>(v >> (8 * i));
    }
    return out;
}  // Scalar::fromUint

auto Scalar::fromUintPow(uint64_t v, uint64_t p) -> Scalar
{
    if (p == 0) return Scalar::fromUint(1);
    const auto value = Scalar::fromUint(v);
    auto result = value;
    for (uint64_t i = 1; i < p; ++i)
    {
        result = result * value;
    }
    return result;
}  // Scalar::fromUintPow

auto Scalar::isZero() const -> bool
{
    return sodium_is_zero(bytes_.data(), bytes_.size()) == 1;
}  // Scalar::isZero

auto Scalar::operator==(const Scalar& rhs) const -> bool
{
    return sodium_memcmp(bytes_.data(), rhs.bytes_.data(), bytes_.size()) == 0;
}  // Scalar::operator==

auto Scalar::operator+(const Scalar& rhs) const -> Scalar
{
    auto out = Scalar{};
    crypto_core_ed25519_scalar_add(
        out.bytes_.data(), bytes_.data(), rhs.bytes_.data()
    );
    return out;
}  // Scalar::operator+

auto Scalar::operator+=(const Scalar& rhs) -> void
{
    *this = *this + rhs;
}  // Scalar::operator+=

auto Scalar::operator-(const Scalar& rhs) const -> Scalar
{
    auto out = Scalar{};
    crypto_core_ed25519_scalar_sub(
        out.bytes_.data(), bytes_.data(), rhs.bytes_.data()
    );
    return out;
}  // Scalar::operator-

auto Scalar::operator*(const Scalar& rhs) const -> Scalar
{
    auto out = Scalar{};
    crypto_core_ed25519_scalar_mul(
        out.bytes_.data(), bytes_.data(), rhs.bytes_.data()
    );
    return out;
}  // Scalar::operator*

auto Scalar::operator/(const Scalar& rhs) const -> Scalar
{
    if (rhs.isZero())
    {
        throw std::invalid_argument("div by zero");
    }
    auto inv = Scalar{};
    if (crypto_core_ed25519_scalar_invert(
            inv.bytes_.data(), rhs.bytes_.data()
        ) != 0)
    {
        throw std::invalid_argument("div by zero");
    }
    return *this * inv;
}  // Scalar::operator/

auto Point::mulBasepoint(const Scalar& s) -> Point
{
    ensureInit();
    auto out = Point{};
    const auto s_bytes = s.bytes();
    // _noclamp: s is already a canonical scalar, so do not clamp it.
    crypto_scalarmult_ed25519_base_noclamp(out.bytes_.data(), s_bytes.data());
    return out;
}  // Point::mulBasepoint

auto Point::operator+(const Point& rhs) const -> Point
{
    ensureInit();
    auto out = Point{};
    if (crypto_core_ed25519_add(
            out.bytes_.data(), bytes_.data(), rhs.bytes_.data()
        ) != 0)
    {
        throw std::invalid_argument("Invalid Ed25519 point in addition.");
    }
    return out;
}  // Point::operator+

auto EncodedPointAdd(
    std::span<const uint8_t, 32> a,
    std::span<const uint8_t, 32> b
) -> std::array<uint8_t, 32>
{
    auto pa = std::array<uint8_t, 32>{};
    auto pb = std::array<uint8_t, 32>{};
    std::copy_n(a.data(), 32, pa.begin());
    std::copy_n(b.data(), 32, pb.begin());
    return (Point{pa} + Point{pb}).bytes();
}  // EncodedPointAdd

}  // namespace cardano::tss::ed25519
