// Copyright (c) 2022 Viper Science LLC
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

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <span>

#ifndef _CARDANO_DEBUG_UTILS_HPP_
#define _CARDANO_DEBUG_UTILS_HPP_

namespace cardano_debug {

static void print_bytes(std::span<const uint8_t> data, size_t line_width = 16) {
    size_t counter = 0;
    for (auto v : data) {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)v << " ";
        counter++;
        if (counter > line_width - 1) {
            std::cout << std::endl;
            counter = 0;
        }
    } 
    std::cout << std::endl;
}

} // namespace cardano_debug

#endif // _CARDANO_DEBUG_UTILS_HPP_