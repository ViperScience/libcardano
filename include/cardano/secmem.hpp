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

#ifndef _CARDANO_SECMEM_HPP_
#define _CARDANO_SECMEM_HPP_

#include <sys/mman.h>

#include <algorithm>
#include <array>

namespace cardano
{

template <std::size_t Size>
struct ByteArray : public std::array<uint8_t, Size>
{
};

template <std::size_t Size>
struct SecureByteArray : public std::array<uint8_t, Size>
{
    SecureByteArray()
    {
        mlock(std::array<uint8_t, Size>::data(), sizeof(uint8_t) * Size);
    }

    ~SecureByteArray()
    {
        char *bytes =
            reinterpret_cast<char *>(std::array<uint8_t, Size>::data());
        std::fill_n<volatile char *>(bytes, sizeof(uint8_t) * Size, 0);
        munlock(bytes, sizeof(uint8_t) * Size);
    }
};  // SecureByteArray

}  // namespace cardano

#endif  // _CARDANO_SECMEM_HPP_