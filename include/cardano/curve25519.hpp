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

#ifndef _CARDANO_CURVE25519_HPP_
#define _CARDANO_CURVE25519_HPP_

// Standard Library Includes
#include <array>
#include <cstdint>
#include <span>

/// @brief Thin wrapper over libsodium's low-level Ed25519 API.
///
/// This shim exposes exactly the scalar (mod the group order ℓ) and curve-point
/// operations that the threshold protocol in `tss.cpp` needs, backed by
/// libsodium's audited, constant-time primitives.
namespace cardano::tss::ed25519
{

/// @brief An integer modulo the Ed25519 group order ℓ, stored canonically as
/// 32 little-endian bytes (always `< ℓ`).
class Scalar
{
  public:
    Scalar() = default;

    /// @brief Wrap raw bytes that are already a canonical scalar (`< ℓ`).
    explicit Scalar(std::array<uint8_t, 32> bytes) : bytes_(bytes) {}

    /// @brief Reduce a 32-byte little-endian value mod ℓ.
    /// For values already `< ℓ` this is a no-op; for clamped `kL ≥ ℓ` it
    /// reduces.
    static auto reduce(std::span<const uint8_t, 32> in) -> Scalar;

    /// @brief Reduce a 64-byte little-endian value mod ℓ.
    static auto reduce(std::span<const uint8_t, 64> in) -> Scalar;

    /// @brief A uniformly random, non-zero scalar in `[1, ℓ)`.
    /// Backed by libsodium's CSPRNG (`crypto_core_ed25519_scalar_random`).
    static auto random() -> Scalar;

    /// @brief Encode an unsigned integer as a scalar.
    static auto fromUint(uint64_t v) -> Scalar;

    /// @brief Compute `v^p mod ℓ`.
    static auto fromUintPow(uint64_t v, uint64_t p) -> Scalar;

    /// @brief The additive identity (0).
    static auto zero() -> Scalar { return Scalar{}; }

    [[nodiscard]] auto isZero() const -> bool;

    /// @brief Constant-time equality.
    auto operator==(const Scalar& rhs) const -> bool;

    auto operator+(const Scalar& rhs) const -> Scalar;
    auto operator+=(const Scalar& rhs) -> void;
    auto operator-(const Scalar& rhs) const -> Scalar;
    auto operator*(const Scalar& rhs) const -> Scalar;

    /// @brief Division mod ℓ via the modular inverse of the denominator.
    /// Throws `std::invalid_argument` when the denominator is zero.
    auto operator/(const Scalar& rhs) const -> Scalar;

    [[nodiscard]] auto bytes() const -> std::array<uint8_t, 32>
    {
        return bytes_;
    }

  private:
    std::array<uint8_t, 32> bytes_{};  // canonical little-endian, < ℓ
};

/// @brief A point on the Ed25519 curve, stored in the standard 32-byte
/// compressed encoding.
class Point
{
  public:
    Point() = default;

    /// @brief Wrap a 32-byte compressed point encoding.
    explicit Point(std::array<uint8_t, 32> bytes) : bytes_(bytes) {}

    /// @brief Compute `[s]B`, the basepoint multiplied by a scalar.
    static auto mulBasepoint(const Scalar& s) -> Point;

    /// @brief Point addition (`crypto_core_ed25519_add`).
    /// Throws `std::invalid_argument` if either operand is not a valid
    /// on-curve encoding.
    auto operator+(const Point& rhs) const -> Point;

    [[nodiscard]] auto bytes() const -> std::array<uint8_t, 32>
    {
        return bytes_;
    }

  private:
    std::array<uint8_t, 32> bytes_{};  // compressed encoding
};

/// @brief Add two Ed25519 public-key / commitment points given by their 32-byte
/// encodings.
auto EncodedPointAdd(
    std::span<const uint8_t, 32> a,
    std::span<const uint8_t, 32> b
) -> std::array<uint8_t, 32>;

}  // namespace cardano::tss::ed25519

#endif  // _CARDANO_CURVE25519_HPP_
