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

#include <algorithm>
#include <string>
#include <vector>

#ifndef _CARDANO_UTILS_HPP_
#define _CARDANO_UTILS_HPP_

namespace cardano
{

template <class SizedRange1, class SizedRange2>
auto concat_bytes(SizedRange1 const &r1, SizedRange2 const &r2)
{
    std::vector<typename SizedRange1::value_type> ret;
    ret.reserve(r1.size() + r2.size());
    ret.insert(ret.end(), std::begin(r1), std::end(r1));
    ret.insert(ret.end(), std::begin(r2), std::end(r2));
    return ret;
}  // concat_bytes

static constexpr auto strcmpi(std::string_view h1, std::string_view h2) -> bool
{
    if (h1.size() != h2.size()) return false;
    for (size_t i = 0; i < h1.size(); ++i)
        if (std::tolower((char)h1[i]) != std::tolower((char)h2[i]))
            return false;
    return true;
}  // strcmpi

}  // namespace cardano

#endif  // _CARDANO_UTILS_HPP_
