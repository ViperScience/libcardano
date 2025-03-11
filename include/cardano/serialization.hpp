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

    /// @brief Virtual method to parse the CBOR structure.
    /// @param data CBOR array object.
    virtual auto deserializer(const cppbor::Array& data) -> void = 0;

    /// @brief Serialize the object as a CBOR byte vector.
    /// @return CBOR byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return serializer().encode();
    }

    /// @brief Deserialize CBOR byte vector.
    /// @param bytes CBOR byte vector.
    auto deserialize(std::span<const uint8_t> bytes) -> void
    {
        auto [item, end, error] = cppbor::parse(bytes.data(), bytes.size());
        if (!item || !error.empty())
        {
            throw std::runtime_error("CBOR parsing failed: " + error);
        }
        if (!item->asArray())
        {
            throw std::runtime_error("Byte vector must be a CBOR array.");
        }
        deserializer(*(item->asArray()));
    }

    virtual ~ArraySerializable() = default;
};  // ArraySerializable

/// @brief Virtual struct defining CBOR map serializability.
struct MapSerializable
{
    /// @brief Virtual method to define a serializing object.
    /// @return CBOR map object.
    [[nodiscard]] virtual auto serializer() const -> cppbor::Map = 0;

    /// @brief Virtual method to parse the CBOR structure.
    /// @param data CBOR map object.
    virtual auto deserializer(const cppbor::Map& data) -> void = 0;

    /// @brief Serialize the object as a CBOR byte vector.
    /// @return CBOR byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return serializer().encode();
    }

    /// @brief Deserialize CBOR byte vector.
    /// @param bytes CBOR byte vector.
    auto deserialize(std::span<const uint8_t> bytes) -> void
    {
        auto [item, end, error] = cppbor::parse(bytes.data(), bytes.size());
        if (!item || !error.empty())
        {
            throw std::runtime_error("CBOR parsing failed: " + error);
        }
        if (!item->asMap())
        {
            throw std::runtime_error("Byte vector must be a CBOR array.");
        }
        deserializer(*(item->asMap()));
    }

    virtual ~MapSerializable() = default;
};  // MapSerializable

/// @brief Virtual struct defining CBOR tagged item serializability.
struct TagSerializable
{
    /// @brief Virtual method to define a serializing object.
    /// @return CBOR tagged item object.
    [[nodiscard]] virtual auto serializer() const -> cppbor::SemanticTag = 0;

    /// @brief Virtual method to parse the CBOR structure.
    /// @param data CBOR SemanticTag object.
    virtual auto deserializer(const cppbor::SemanticTag& data) -> void = 0;

    /// @brief Serialize the object as a CBOR byte vector.
    /// @return CBOR byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return serializer().encode();
    }

    /// @brief Deserialize CBOR byte vector.
    /// @param bytes CBOR byte vector.
    auto deserialize(std::span<const uint8_t> bytes) -> void
    {
        auto [item, end, error] = cppbor::parse(bytes.data(), bytes.size());
        if (!item || !error.empty())
        {
            throw std::runtime_error("CBOR parsing failed: " + error);
        }
        if (!item->asSemanticTag())
        {
            throw std::runtime_error("Byte vector must be a CBOR array.");
        }
        deserializer(*(item->asSemanticTag()));
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

    /// Serialize as 2-elem array with tag 6.30
    [[nodiscard]] auto serializer() const -> cppbor::SemanticTag override
    {
        return cppbor::SemanticTag{30, cppbor::Array{num, den}};
    }  // serializer

    /// Deserialize the two values from the CBOR object
    auto deserializer(const cppbor::SemanticTag& data) -> void override
    {
        if (data.semanticTag() != 30)
        {
            throw std::runtime_error(
                "Invalid tag for Rational: expected 30, got " +
                std::to_string(data.semanticTag())
            );
        }

        if (!data.asArray())
        {
            throw std::runtime_error("Rational data must be a CBOR array");
        }

        if (data.asArray()->size() != 2)
        {
            throw std::runtime_error(
                "Rational array must have exactly 2 elements"
            );
        }

        const auto arr = data.asArray();
        if (!(arr->get(0)->asUint()) || !(arr->get(1)->asUint()))
        {
            throw std::runtime_error(
                "Rational elements must be unsigned integers"
            );
        }

        this->num = arr->get(0)->asUint()->unsignedValue();
        this->den = arr->get(1)->asUint()->unsignedValue();

        if (this->den == 0)
        {
            throw std::runtime_error("Denominator cannot be zero");
        }
    }  // deserializer
};  // Rational

}  // namespace cardano

#endif  // _CARDANO_SERIALIZATION_HPP_
