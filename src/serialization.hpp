// Copyright (c) 2021-2024 Viper Science LLC
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

#ifndef _CARDANO_SERIALIZATION_HPP_
#define _CARDANO_SERIALIZATION_HPP_

#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

namespace cardano
{

/// @brief Virtual struct defining CBOR array serializability.
struct ArraySerializable
{
    /// @brief Virtual method to define a serializing object.
    /// @return CBOR array object.
    [[nodiscard]] virtual auto serializer() const -> cppbor::Array = 0;

    /// @brief Serialize the object as a CBOR byte vector.
    /// @return CBOR byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return serializer().encode();
    }

    virtual ~ArraySerializable() = default;
};  // ArraySerializable

/// @brief Virtual struct defining CBOR map serializability.
struct MapSerializable
{
    /// @brief Virtual method to define a serializing object.
    /// @return CBOR map object.
    [[nodiscard]] virtual auto serializer() const -> cppbor::Map = 0;

    /// @brief Serialize the object as a CBOR byte vector.
    /// @return CBOR byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return serializer().encode();
    }

    virtual ~MapSerializable() = default;
};  // MapSerializable

/// @brief Virtual struct defining CBOR tagged item serializability.
struct TagSerializable
{
    /// @brief Virtual method to define a serializing object.
    /// @return CBOR tagged item object.
    [[nodiscard]] virtual auto serializer() const -> cppbor::SemanticTag = 0;

    /// @brief Serialize the object as a CBOR byte vector.
    /// @return CBOR byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return serializer().encode();
    }

    virtual ~TagSerializable() = default;
};  // TagSerializable

/// @brief Represent a rational number (numerator and denominator).
/// @note A rational number in CBOR has the tag 30 and consists of a two-element
/// array of unsigned integers.
struct Rational : public TagSerializable
{
    Rational() : num{0}, den{1} {}
    Rational(uint64_t n, uint64_t d) : num{n}, den{d} {}
    uint64_t num;
    uint64_t den;

    // Serialize as 2-elem array with tag 6.30
    [[nodiscard]] auto serializer() const -> cppbor::SemanticTag
    {
        return cppbor::SemanticTag{30, cppbor::Array{num, den}};
    }  // serializer
};  // Rational

}  // namespace cardano

#endif  // _CARDANO_SERIALIZATION_HPP_
