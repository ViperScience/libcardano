// MIT License
//
// Copyright (c) 2021-2025 Viper Staking
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
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstring>

#include <botan/mem_ops.h>
#include <cardano/secmem.hpp>

TEST_CASE("testSecureByteArraySecurity")
{
    SECTION("testMemoryZeroingOnDestruction")
    {
        // Use placement new with controlled buffer
        alignas(cardano::SecureByteArray<32>) unsigned char
            buffer[sizeof(cardano::SecureByteArray<32>)];

        // Fill buffer with non-zero pattern
        std::memset(buffer, 0xFF, sizeof(buffer));

        {
            // Create SecureByteArray in the buffer
            auto* secure_array = new (buffer) cardano::SecureByteArray<32>();

            // Fill with sensitive data
            std::fill(secure_array->begin(), secure_array->end(), 0xDE);

            // Verify data is there
            REQUIRE((*secure_array)[0] == 0xDE);
            REQUIRE((*secure_array)[31] == 0xDE);

            // Explicitly call destructor
            secure_array->~SecureByteArray();
        }

        // Verify the actual data area (first 32 bytes) is zeroed
        bool data_zeroed = std::all_of(
            buffer, buffer + 32, [](unsigned char b) { return b == 0x00; }
        );

        REQUIRE(data_zeroed);
    }

    SECTION("testBotanSecureScrubAvailable")
    {
        // Verify Botan::secure_scrub_memory works correctly
        std::array<uint8_t, 64> test_data;
        test_data.fill(0xAB);

        // Call Botan's secure scrubbing
        Botan::secure_scrub_memory(test_data.data(), test_data.size());

        // Verify it's zeroed
        bool all_zero = std::all_of(
            test_data.begin(),
            test_data.end(),
            [](uint8_t b) { return b == 0x00; }
        );
        REQUIRE(all_zero);
    }
}
