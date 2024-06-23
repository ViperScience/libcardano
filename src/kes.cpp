// Copyright (c) 2024 Viper Science LLC
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

// Public libcardano Headers
#include <cardano/kes.hpp>

// Third-Party Libraries
#include <botan/hash.h>

using namespace cardano;

auto KesSeed::split(
    std::span<uint8_t, KesSeed::size> seed,
    std::span<uint8_t, KesSeed::size> left_split,
    std::span<uint8_t, KesSeed::size> right_split
) -> void
{
    static constexpr auto one = std::array<uint8_t, 1>{1};
    static constexpr auto two = std::array<uint8_t, 1>{2};

    const auto hasher = Botan::HashFunction::create("Blake2b(256)");
    hasher->update(one.data(), one.size());
    hasher->update(seed.data(), seed.size());
    hasher->final(left_split.data());  // Hasher is reset here
    hasher->update(two.data(), two.size());
    hasher->update(seed.data(), seed.size());
    hasher->final(right_split.data());

    Botan::secure_scrub_memory(seed.data(), seed.size());
}  // KesSeed::split

auto KesPublicKey::hash_pair(const KesPublicKey& other) const -> KesPublicKey
{
    auto out = std::array<uint8_t, KesPublicKey::size>();
    const auto hasher = Botan::HashFunction::create("Blake2b(256)");
    hasher->update(this->bytes().data(), KesPublicKey::size);
    hasher->update(other.bytes().data(), KesPublicKey::size);
    hasher->final(out.data());
    return KesPublicKey(out);
}  // KesPublicKey::hash_pair