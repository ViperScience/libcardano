// Copyright (c) 2021 Viper Science LLC
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

// Standard library headers
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

// Third-party QCBOR library for CBOR functionality
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

// Libcardano headers
#include <cardano/encodings.hpp>

#include "utils.hpp"

using namespace cardano;

auto bytes2hex(std::span<const uint8_t> bytes) -> std::string
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    auto first = bytes.begin();
    while (first != bytes.end())
        ss << std::setw(2) << static_cast<int>(*first++);
    return ss.str();
}  // bytes2hex

auto hex2bytes(std::string_view hex) -> std::vector<uint8_t>
{
    // Ensure an even number of characters in the string
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Not a valid hexadecimal string.");
    // Verify only hexadecimal characters
    if (hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        throw std::invalid_argument("Not a valid hexadecimal string.");
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    uint8_t byte;
    auto hex_ptr = hex.data();
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        auto res = std::from_chars(hex_ptr, hex_ptr + 2, byte, 16);
        if (res.ec != std::errc())
            throw std::invalid_argument("Invalid hex character found.");
        bytes.push_back(byte);
        hex_ptr += 2;
    }
    return bytes;
}  // hex2bytes

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// BASE16 ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

auto BASE16::encode(std::span<const uint8_t> bytes) -> std::string
{
    return bytes2hex(bytes);
}  // BASE16::encode

std::vector<uint8_t> BASE16::decode(std::string_view hex)
{
    return hex2bytes(hex);
}  // BASE16::decode

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// BECH32 ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// The Bech32 character set for encoding.
static constexpr std::string_view B32_CHARSET =
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The Bech32 character set for decoding.
static constexpr int8_t B32_CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

/// This function will compute what 6 5-bit values to XOR into the last 6 input
/// values, in order to make the checksum 0. These 6 values are packed together
/// in a single 30-bit integer. The higher bits correspond to earlier values.
static constexpr auto polymod(std::span<const uint8_t> values) -> uint32_t
{
    // The input is interpreted as a list of coefficients of a polynomial over F
    // = GF(32), with an implicit 1 in front. If the input is [v0,v1,v2,v3,v4],
    // that polynomial is v(x) = 1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4.
    // The implicit 1 guarantees that [v0,v1,v2,...] has a distinct checksum
    // from [0,v0,v1,v2,...].

    // The output is a 30-bit integer whose 5-bit groups are the coefficients of
    // the remainder of v(x) mod g(x), where g(x) is the Bech32 generator, x^6 +
    // {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}. g(x) is chosen in
    // such a way that the resulting code is a BCH code, guaranteeing detection
    // of up to 3 errors within a window of 1023 characters. Among the various
    // possible BCH codes, one was selected to in fact guarantee detection of up
    // to 4 errors within a window of 89 characters.

    // Note that the coefficients are elements of GF(32), here represented as
    // decimal numbers between {}. In this finite field, addition is just XOR of
    // the corresponding numbers. For example, {27} + {13} = {27 ^ 13} = {22}.
    // Multiplication is more complicated, and requires treating the bits of
    // values themselves as coefficients of a polynomial over a smaller field,
    // GF(2), and multiplying those polynomials mod a^5 + a^3 + 1. For example,
    // {5} * {26} = (a^2 + 1) * (a^4 + a^3 + a) = (a^4 + a^3 + a) * a^2 + (a^4 +
    // a^3 + a) = a^6 + a^5 + a^4 + a = a^3 + 1 (mod a^5 + a^3 + 1) = {9}.

    // During the course of the loop below, `c` contains the bitpacked
    // coefficients of the polynomial constructed from just the values of v that
    // were processed so far, mod g(x). In the above example, `c` initially
    // corresponds to 1 mod g(x), and after processing 2 inputs of v, it
    // corresponds to x^2 + v0*x + v1 mod g(x). As 1 mod g(x) = 1, that is the
    // starting value for `c`.
    uint32_t c = 1;
    for (const auto v_i : values)
    {
        // We want to update `c` to correspond to a polynomial with one extra
        // term. If the initial value of `c` consists of the coefficients of
        // c(x) = f(x) mod g(x), we modify it to correspond to c'(x) = (f(x) * x
        // + v_i) mod g(x), where v_i is the next input to process. Simplifying:
        // c'(x) = (f(x) * x + v_i) mod g(x)
        //         ((f(x) mod g(x)) * x + v_i) mod g(x)
        //         (c(x) * x + v_i) mod g(x)
        // If c(x) = c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5, we want to
        // compute c'(x) = (c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5) * x +
        // v_i mod g(x)
        //       = c0*x^6 + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i mod
        //       g(x) = c0*(x^6 mod g(x)) + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 +
        //       c5*x + v_i
        // If we call (x^6 mod g(x)) = k(x), this can be written as
        // c'(x) = (c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i) + c0*k(x)

        // First, determine the value of c0:
        uint8_t c0 = c >> 25;

        // Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i:
        c = ((c & 0x1ffffff) << 5) ^ v_i;

        // Finally, for each set bit n in c0, conditionally add {2^n}k(x):
        if (c0 & 1)
            c ^= 0x3b6a57b2;  //     k(x) = {29}x^5 + {22}x^4 + {20}x^3 +
                              //     {21}x^2 + {29}x + {18}
        if (c0 & 2)
            c ^= 0x26508e6d;  //  {2}k(x) = {19}x^5 +  {5}x^4 +     x^3 + {3}x^2
                              //  + {19}x + {13}
        if (c0 & 4)
            c ^= 0x1ea119fa;  //  {4}k(x) = {15}x^5 + {10}x^4 +  {2}x^3 + {6}x^2
                              //  + {15}x + {26}
        if (c0 & 8)
            c ^= 0x3d4233dd;  //  {8}k(x) = {30}x^5 + {20}x^4 +  {4}x^3 +
                              //  {12}x^2 + {30}x + {29}
        if (c0 & 16)
            c ^= 0x2a1462b3;  // {16}k(x) = {21}x^5 +     x^4 +  {8}x^3 +
                              // {24}x^2 + {21}x + {19}
    }
    return c;
}  // polymod

/// Expand a HRP for use in checksum computation.
auto expand_hrp(std::string_view hrp) -> std::vector<uint8_t>
{
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() + 90);
    ret.resize(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i)
    {
        uint8_t c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp.size() + 1] = c & 0x1f;
    }
    ret[hrp.size()] = 0;
    return ret;
}  // expand_hrp

/// Verify a checksum.
auto verify_checksum(std::string_view hrp, std::span<const uint8_t> values)
    -> bool
{
    // PolyMod computes what value to xor into the final values to make the
    // checksum 0. However, if we required that the checksum was 0, it would be
    // the case that appending a 0 to a valid list of values would result in a
    // new valid list. For that reason, Bech32 requires the resulting checksum
    // to be 1 instead.
    const uint32_t check = polymod(concat_bytes(expand_hrp(hrp), values));
    return check == 1;
}  // verify_checksum

auto create_checksum(std::string_view hrp, std::span<const uint8_t> values)
    -> std::vector<uint8_t>
{
    std::vector<uint8_t> enc = concat_bytes(expand_hrp(hrp), values);
    enc.resize(enc.size() + 6);
    const uint32_t mod = polymod(enc) ^ 1;
    std::vector<uint8_t> ret;
    ret.resize(6);
    for (size_t i = 0; i < 6; ++i)
    {
        // Convert the 5-bit groups in mod to checksum values.
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}  // create_checksum

auto convertbits(
    std::span<const uint8_t> data, int frombits, int tobits, bool pad
) -> std::vector<uint8_t>
{
    int acc = 0;
    int bits = 0;
    std::vector<uint8_t> ret;
    int maxv = (1 << tobits) - 1;
    int max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (const auto &value : data)
    {
        if (value < 0 or (value >> frombits))
            throw std::invalid_argument("Invalid bits.");
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits)
        {
            bits -= tobits;
            ret.push_back((acc >> bits) & maxv);
        }
    }

    if (pad)
    {
        if (bits != 0) ret.push_back((acc << (tobits - bits)) & maxv);
    }
    else if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
    {
        throw std::invalid_argument("Invalid bit conversion.");
    }

    return ret;
}  // convertbits

auto BECH32::encode(std::string_view hrp, std::span<const uint8_t> values)
    -> std::string
{
    // First ensure that the HRP is all lowercase. BIP-173 requires an encoder
    // to return a lowercase Bech32 string, but if given an uppercase HRP, the
    // result will always be invalid.
    for (const char &c : hrp)
        if (!(c < 'A' || c > 'Z'))
            throw std::invalid_argument(
                "Invalid HRP, the HRB cannot be uppercase."
            );
    auto unpacked_values = convertbits(values, 8, 5, true);
    auto checksum = create_checksum(hrp, unpacked_values);
    auto combined = concat_bytes(unpacked_values, checksum);
    auto ret = std::string(hrp) + '1';
    ret.reserve(ret.size() + combined.size());
    for (const auto c : combined) ret += B32_CHARSET[c];
    return ret;
}  // BECH32::encode

auto BECH32::decode(std::string_view str)
    -> std::pair<std::string, std::vector<uint8_t>>
{
    auto bech32_str = std::string(str);

    // Ensure the string characters are all lower case.
    auto make_lower = [](unsigned char c) { return std::tolower(c); };
    std::transform(
        bech32_str.begin(), bech32_str.end(), bech32_str.begin(), make_lower
    );

    // Find the separator.
    size_t bech32_str_size = str.size();
    size_t pos = bech32_str.rfind('1');
    if (pos == bech32_str.npos || pos == 0 || pos + 7 > bech32_str_size)
        throw std::invalid_argument(
            "The given string is not valid bech32 format."
        );

    // Extract the data values.
    std::vector<uint8_t> values(bech32_str_size - 1 - pos);
    for (size_t i = 0; i < bech32_str_size - 1 - pos; ++i)
    {
        unsigned char c = bech32_str[i + pos + 1];
        int8_t rev = B32_CHARSET_REV[c];
        if (rev == -1)
        {
            throw std::invalid_argument("Invalid bech32 character found.");
        }
        values[i] = rev;
    }

    // Save the HRP
    auto hrp = std::string(bech32_str.begin(), bech32_str.begin() + pos);

    // Verify the checksum of the data
    if (!verify_checksum(hrp, values))
        throw std::invalid_argument("Invalid bech32 checksum found.");

    // Pack the bits (cardano needs to pack the bits...)
    values.resize(values.size() - 6);  // trim the checksum
    auto packed_values = convertbits(values, 5, 8, false);
    return std::make_pair(hrp, packed_values);
}  // BECH32::decode

auto BECH32::encode_hex(std::string_view hrp, std::string_view hex_values)
    -> std::string
{
    auto values_bytes = hex2bytes(hex_values);
    return BECH32::encode(hrp, values_bytes);
}  // BECH32::encode_hex

auto BECH32::decode_hex(std::string_view bech32_str)
    -> std::pair<std::string, std::string>
{
    auto [hrp, data] = cardano::BECH32::decode(bech32_str);
    auto hex_str = bytes2hex(data);
    return std::make_pair(hrp, hex_str);
}  // BECH32::decode_hex

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// BASE58 ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/** The Base58 character set for encoding. */
static constexpr uint8_t B58_CHARSET[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

static constexpr int8_t B58_CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1};

auto BASE58::encode(std::span<const uint8_t> values) -> std::string
{
    std::vector<uint8_t> digits((values.size() * 138 / 100) + 1);
    size_t digitslen = 1;
    for (size_t i = 0; i < values.size(); i++)
    {
        uint32_t carry = static_cast<uint32_t>(values[i]);
        for (size_t j = 0; j < digitslen; j++)
        {
            carry = carry + static_cast<uint32_t>(digits[j] << 8);
            digits[j] = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        for (; carry; carry /= 58)
            digits[digitslen++] = static_cast<uint8_t>(carry % 58);
    }
    std::string result;
    for (size_t i = 0; i < (values.size() - 1) && !values[i]; i++)
        result.push_back(B58_CHARSET[0]);
    for (size_t i = 0; i < digitslen; i++)
        result.push_back(B58_CHARSET[digits[digitslen - 1 - i]]);
    return result;
}  // BASE58::encode

auto BASE58::decode(std::string_view str) -> std::vector<uint8_t>
{
    std::vector<uint8_t> result;
    result.push_back(0);
    int res_len = 1;
    int enc_len = str.length();
    for (int i = 0; i < enc_len; i++)
    {
        auto charset_index = static_cast<uint8_t>(str[i]);
        unsigned int carry = (unsigned int)B58_CHARSET_REV[charset_index];
        for (int j = 0; j < res_len; j++)
        {
            carry += (unsigned int)(result[j]) * 58;
            result[j] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0)
        {
            res_len++;
            result.push_back((uint8_t)(carry & 0xff));
            carry >>= 8;
        }
    }

    for (int i = 0; i < enc_len && str[i] == '1'; i++)
    {
        res_len++;
        result.push_back(0);
    }

    for (int i = res_len - 1, z = (res_len >> 1) + (res_len & 1); i >= z; i--)
    {
        int k = result[i];
        result[i] = result[res_len - i - 1];
        result[res_len - i - 1] = k;
    }
    return result;
}  // BASE58::decode

auto BASE58::encode_hex(std::string_view hex_values) -> std::string
{
    auto values_bytes = hex2bytes(hex_values);
    return BASE58::encode(values_bytes);
}  // BASE58::encode_hex

auto BASE58::decode_hex(std::string_view base58_str) -> std::string
{
    auto data = cardano::BASE58::decode(base58_str);
    return bytes2hex(data);
}  // BASE58::decode_hex

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// CBOR /////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

auto CBOR::encode(std::span<const uint8_t> data) -> std::vector<uint8_t>
{
    // We have to pre-allocate the buffer used for writing the CBOR and it
    // cannot be undersized. Here we assume that allocating on the stack is
    // acceptible and just double the size of the input bytes. This could be
    // optimized in the future.
    UsefulBuf_MAKE_STACK_UB(buffer, 2 * data.size());
    QCBOREncodeContext encodeCtx;
    QCBOREncode_Init(&encodeCtx, buffer);
    QCBOREncode_AddBytes(&encodeCtx, (UsefulBufC){data.data(), data.size()});
    UsefulBufC encodedCBOR;
    auto uErr = QCBOREncode_Finish(&encodeCtx, &encodedCBOR);
    if (uErr != QCBOR_SUCCESS) std::runtime_error("Invalid CBOR bytes.");
    return std::vector<uint8_t>(
        (uint8_t *)encodedCBOR.ptr, (uint8_t *)encodedCBOR.ptr + encodedCBOR.len
    );
}  // CBOR::encode

auto CBOR::encode(uint64_t v) -> std::vector<uint8_t>
{
    UsefulBuf_MAKE_STACK_UB(buffer, sizeof(uint64_t));
    QCBOREncodeContext encodeCtx;
    QCBOREncode_Init(&encodeCtx, buffer);
    QCBOREncode_AddUInt64(&encodeCtx, v);
    UsefulBufC encodedCBOR;
    auto uErr = QCBOREncode_Finish(&encodeCtx, &encodedCBOR);
    if (uErr != QCBOR_SUCCESS) std::runtime_error("Invalid CBOR bytes.");
    return std::vector<uint8_t>(
        (uint8_t *)encodedCBOR.ptr, (uint8_t *)encodedCBOR.ptr + encodedCBOR.len
    );
}  // CBOR::encode

auto CBOR::decodeUint32(std::span<const uint8_t> b) -> uint32_t
{
    int64_t temp;
    uint32_t ret_val;
    QCBORDecodeContext ctx;
    auto bytes = (UsefulBufC){b.data(), b.size()};
    QCBORDecode_Init(&ctx, bytes, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetInt64(&ctx, &temp);
    if (ctx.uLastError != QCBOR_SUCCESS)
        throw std::logic_error("Unexpected CBOR data");
    QCBOR_Int64ToUInt32(temp, &ret_val);
    return ret_val;
}  // CBOR::decodeUint32

auto CBOR::decodeBytes(std::span<const uint8_t> b) -> std::vector<uint8_t>
{
    auto ctx = QCBORDecodeContext();
    auto buf = UsefulBufC();
    auto bytes = (UsefulBufC){b.data(), b.size()};
    QCBORDecode_Init(&ctx, bytes, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetByteString(&ctx, &buf);
    if (ctx.uLastError != QCBOR_SUCCESS)
        throw std::logic_error("Unexpected CBOR data");
    auto ptr = (uint8_t *)buf.ptr;
    return std::vector<uint8_t>(ptr, ptr + buf.len);
}  // CBOR::decodeBytes

CBOR::Encoder::Encoder(const size_t buff_size)
{
    this->_cbor_ctx = std::make_shared<QCBOREncodeContext>();
    this->_cbor_buf = std::shared_ptr<uint8_t>(
        new uint8_t[buff_size], [](uint8_t *p) { delete[] p; }
    );
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_Init(ctx.get(), (UsefulBuf){this->_cbor_buf.get(), buff_size});
}  // CBOR::Encoder::Encoder

auto CBOR::Encoder::startArray() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_OpenArray(ctx.get());
}  // CBOR::Encoder::startArray

auto CBOR::Encoder::startArrayInMap(int64_t k) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_OpenArrayInMapN(ctx.get(), k);
}  // CBOR::Encoder::startArrayInMap

auto CBOR::Encoder::endArray() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_CloseArray(ctx.get());
}  // CBOR::Encoder::endArray

auto CBOR::Encoder::newArray(const size_t buff_size) -> CBOR::Encoder
{
    auto cbor_obj = CBOR::Encoder(buff_size);
    cbor_obj.startArray();
    return cbor_obj;
}  // CBOR::newArray

auto CBOR::Encoder::startIndefArray() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_OpenArrayIndefiniteLength(ctx.get());
}  // CBOR::Encoder::startIndefArray

auto CBOR::Encoder::endIndefArray() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_CloseArrayIndefiniteLength(ctx.get());
}  // CBOR::Encoder::endIndefArray

auto CBOR::Encoder::newIndefArray(const size_t buff_size) -> CBOR::Encoder
{
    auto cbor_obj = CBOR::Encoder(buff_size);
    cbor_obj.startIndefArray();
    return cbor_obj;
}  // CBOR::newIndefArray

auto CBOR::Encoder::startMap() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_OpenMap(ctx.get());
}  // CBOR::Encoder::startMap

auto CBOR::Encoder::startMapInMap(int64_t k) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_OpenMapInMapN(ctx.get(), k);
}  // CBOR::Encoder::startMapInMap

auto CBOR::Encoder::endMap() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_CloseMap(ctx.get());
}  // CBOR::Encoder::endMap

auto CBOR::Encoder::newMap(const size_t buff_size) -> CBOR::Encoder
{
    auto cbor_obj = CBOR::Encoder(buff_size);
    cbor_obj.startMap();
    return cbor_obj;
}  // CBOR::Encoder::newMap

auto CBOR::Encoder::startIndefMap() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_OpenMapIndefiniteLength(ctx.get());
}  // CBOR::Encoder::startMap

auto CBOR::Encoder::endIndefMap() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_CloseMapIndefiniteLength(ctx.get());
}  // CBOR::Encoder::endMap

auto CBOR::Encoder::newIndefMap(const size_t buff_size) -> CBOR::Encoder
{
    auto cbor_obj = CBOR::Encoder(buff_size);
    cbor_obj.startIndefMap();
    return cbor_obj;
}  // CBOR::Encoder::newMap

auto CBOR::Encoder::add(int64_t v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddInt64(ctx.get(), v);
}  // CBOR::Encoder::add

auto CBOR::Encoder::add(std::span<const uint8_t> bytes) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddBytes(ctx.get(), ((UsefulBufC){bytes.data(), bytes.size()}));
}  // CBOR::Encoder::add

auto CBOR::Encoder::addBool(bool v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddBool(ctx.get(), v);
}  // CBOR::Encoder::addBool

auto CBOR::Encoder::addNULL() -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddNULL(ctx.get());
}  // CBOR::Encoder::addNULL

auto CBOR::Encoder::addToMap(std::string_view k, int64_t v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddInt64ToMap(ctx.get(), k.data(), v);
}  // CBOR::Encoder::addToMap

auto CBOR::Encoder::addToMap(std::string_view k, std::span<const uint8_t> v)
    -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddBytesToMap(
        ctx.get(), k.data(), ((UsefulBufC){v.data(), v.size()})
    );
}  // CBOR::Encoder::addToMap

auto CBOR::Encoder::addToMap(int64_t k, int64_t v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddInt64(ctx.get(), k);
    QCBOREncode_AddInt64(ctx.get(), v);
}  // CBOR::Encoder::addToMap

auto CBOR::Encoder::addToMap(int64_t key, std::span<const uint8_t> v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddBytesToMapN(
        ctx.get(), key, ((UsefulBufC){v.data(), v.size()})
    );
}  // CBOR::Encoder::addToMap

auto CBOR::Encoder::addEncoded(std::span<const uint8_t> v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddEncoded(ctx.get(), ((UsefulBufC){v.data(), v.size()}));
}  // CBOR::Encoder::addEncoded

auto CBOR::Encoder::addTagged(int64_t tag, std::span<const uint8_t> v) -> void
{
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    QCBOREncode_AddTag(ctx.get(), tag);
    this->add(v);
}  // CBOR::Encoder::addTagged

auto CBOR::Encoder::serialize() -> std::vector<uint8_t>
{
    UsefulBufC buf;
    auto ctx = std::static_pointer_cast<QCBOREncodeContext>(this->_cbor_ctx);
    auto uErr = QCBOREncode_Finish(ctx.get(), &buf);
    if (uErr != QCBOR_SUCCESS)
        std::runtime_error(
            "The CBOR structure is invalid and can not be serialized."
        );
    auto buf_ptr = (uint8_t *)buf.ptr;
    return std::vector<uint8_t>(buf_ptr, buf_ptr + buf.len);
}  // CBOR::Encoder::serialize

CBOR::Decoder::Decoder(std::span<const uint8_t> data)
{
    this->_cbor_bytes.assign(data.begin(), data.end());
    this->_cbor_itm = std::make_shared<QCBORItem>();
    this->_cbor_ctx = std::make_shared<QCBORDecodeContext>();
    QCBORDecode_Init(
        std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx).get(),
        (UsefulBufC){this->_cbor_bytes.data(), this->_cbor_bytes.size()},
        QCBOR_DECODE_MODE_NORMAL
    );
}  // CBOR::Decoder::Decoder

auto CBOR::Decoder::enterArray() -> void
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_EnterArray(ctx.get(), itm.get());
    if (itm->uDataType != QCBOR_TYPE_ARRAY)
        std::invalid_argument("Not a valid CBOR array.");
}  // CBOR::Decoder::enterMap

auto CBOR::Decoder::enterArrayFromMap(int64_t k) -> void
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetItemInMapN(ctx.get(), k, QCBOR_TYPE_ARRAY, itm.get());
    if (itm.get()->uDataType != QCBOR_TYPE_ARRAY)
        throw std::invalid_argument("Not in a CBOR array structure.");
    QCBORDecode_EnterArrayFromMapN(ctx.get(), k);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Invalid CBOR data.");
}  // CBOR::Decoder::enterArrayFromMap

auto CBOR::Decoder::exitArray() -> void
{
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_ExitArray(ctx.get());
}  // CBOR::Decoder::exitArray

auto CBOR::Decoder::fromArrayData(std::span<const uint8_t> cbor_data)
    -> CBOR::Decoder
{
    auto decoder = CBOR::Decoder(cbor_data);
    decoder.enterArray();
    return decoder;
}  // CBOR::Decoder::fromArrayData

auto CBOR::Decoder::getArraySize() -> size_t
{
    const auto pMe = (QCBORItem *)this->_cbor_itm.get();
    if (pMe->uDataType != QCBOR_TYPE_ARRAY)
        throw std::invalid_argument("Not in a CBOR array structure.");
    return (size_t)pMe->val.uCount;
}  // CBOR::Decoder::getArraySize

auto CBOR::Decoder::enterMap() -> void
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_EnterMap(ctx.get(), itm.get());
    if (itm->uDataType != QCBOR_TYPE_MAP)
        std::invalid_argument("Not a valid CBOR map.");
}  // CBOR::Decoder::enterMap

auto CBOR::Decoder::enterMapFromMap(int64_t k) -> void
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetItemInMapN(ctx.get(), k, QCBOR_TYPE_MAP, itm.get());
    if (itm.get()->uDataType != QCBOR_TYPE_MAP)
        throw std::invalid_argument("Not in a CBOR map structure.");
    QCBORDecode_EnterMapFromMapN(ctx.get(), k);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Invalid CBOR data.");
}  // CBOR::Decoder::enterMapFromMap

auto CBOR::Decoder::exitMap() -> void
{
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_ExitMap(ctx.get());
}  // CBOR::Decoder::exitMap

auto CBOR::Decoder::fromMapData(std::span<const uint8_t> cbor_data)
    -> CBOR::Decoder
{
    auto decoder = CBOR::Decoder(cbor_data);
    decoder.enterMap();
    return decoder;
}  // CBOR::Decoder::fromMapData

auto CBOR::Decoder::getMapSize() -> size_t
{
    const auto pMe = (QCBORItem *)this->_cbor_itm.get();
    if (pMe->uDataType != QCBOR_TYPE_MAP)
        throw std::invalid_argument("Not in a CBOR map structure.");
    return (size_t)pMe->val.uCount;
}  // CBOR::Decoder::getMapSize

auto CBOR::Decoder::getSkip() -> void
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetNext(ctx.get(), itm.get());
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Invalid CBOR data.");
}  // CBOR::Decoder::getSkip

auto CBOR::Decoder::getInt64() -> int64_t
{
    int64_t retVal;
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetInt64(ctx.get(), &retVal);
    return retVal;
}  // CBOR::Decoder::getInt64

auto CBOR::Decoder::getInt32() -> int32_t
{
    int32_t ret_val;
    int64_t temp = this->getInt64();
    QCBOR_Int64ToInt32(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getInt32

auto CBOR::Decoder::getInt16() -> int16_t
{
    int16_t ret_val;
    int64_t temp = this->getInt64();
    QCBOR_Int64ToInt16(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getInt16

auto CBOR::Decoder::getInt8() -> int8_t
{
    int8_t ret_val;
    int64_t temp = this->getInt64();
    QCBOR_Int64ToInt8(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getInt8

auto CBOR::Decoder::getUint64() -> uint64_t
{
    uint64_t ret_val;
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetUInt64(ctx.get(), &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint64

auto CBOR::Decoder::getUint32() -> uint32_t
{
    uint32_t ret_val;
    int64_t temp = this->getInt64();
    QCBOR_Int64ToUInt32(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint32

auto CBOR::Decoder::getUint16() -> uint16_t
{
    uint16_t ret_val;
    int64_t temp = this->getInt64();
    QCBOR_Int64UToInt16(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint16

auto CBOR::Decoder::getUint8() -> uint8_t
{
    uint8_t ret_val;
    int64_t temp = this->getInt64();
    QCBOR_Int64ToUInt8(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint8

auto CBOR::Decoder::getBytes() -> std::vector<uint8_t>
{
    auto buf = UsefulBufC();
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetByteString(ctx.get(), &buf);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Invalid CBOR data.");
    auto ptr = (uint8_t *)buf.ptr;
    return std::vector<uint8_t>(ptr, ptr + buf.len);
}  // CBOR::Decoder::getBytes

auto CBOR::Decoder::getString() -> std::string
{
    auto buf = UsefulBufC();
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetTextString(ctx.get(), &buf);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Invalid CBOR data.");
    return std::string(reinterpret_cast<char const *>(buf.ptr), buf.len);
}  // CBOR::Decoder::getString

auto CBOR::Decoder::getNULL() -> bool
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetNext(ctx.get(), itm.get());
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Invalid CBOR data.");
    if (itm->uDataType != QCBOR_TYPE_NULL)
        return false;  // Not a CBOR simple NULL type.
    return true;
}  // CBOR::Decoder::getNULL

auto CBOR::Decoder::getInt64FromMap(int64_t k) -> int64_t
{
    int64_t ret_val;
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetInt64InMapN(ctx.get(), k, &ret_val);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::logic_error("Unexpected CBOR data format.");
    return ret_val;
}  // CBOR::Decoder::getInt64FromMap

auto CBOR::Decoder::getUint8FromMap(int64_t k) -> uint8_t
{
    uint8_t ret_val;
    int64_t temp = this->getInt64FromMap(k);
    QCBOR_Int64ToUInt8(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint8FromMap

auto CBOR::Decoder::getUint16FromMap(int64_t k) -> uint16_t
{
    uint16_t ret_val;
    int64_t temp = this->getInt64FromMap(k);
    QCBOR_Int64UToInt16(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint16FromMap

auto CBOR::Decoder::getUint32FromMap(int64_t k) -> uint32_t
{
    uint32_t ret_val;
    int64_t temp = this->getInt64FromMap(k);
    QCBOR_Int64ToUInt32(temp, &ret_val);
    return ret_val;
}  // CBOR::Decoder::getUint32FromMap

auto CBOR::Decoder::getUint64FromMap(int64_t k) -> uint64_t
{
    uint64_t ret_val;
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetUInt64InMapN(ctx.get(), k, &ret_val);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::logic_error("Unexpected CBOR data format.");
    return ret_val;
}  // CBOR::Decoder::getUint64FromMap

auto CBOR::Decoder::getBytesFromMap(int64_t k) -> std::vector<uint8_t>
{
    auto buf = UsefulBufC();
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetByteStringInMapN(ctx.get(), k, &buf);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Unexpected CBOR data format.");
    auto ptr = (uint8_t *)buf.ptr;
    return std::vector<uint8_t>(ptr, ptr + buf.len);
}  // CBOR::Decoder::getBytesFromMap

auto CBOR::Decoder::getTaggedCborBytes() -> std::vector<uint8_t>
{
    auto buf = UsefulBufC();
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_EnterBstrWrapped(ctx.get(), QCBOR_TAG_REQUIREMENT_TAG, &buf);
    auto tag = QCBORDecode_GetNthTagOfLast(ctx.get(), 0);
    if (tag != 24) std::runtime_error("Invalid tag");
    QCBORDecode_ExitBstrWrapped(ctx.get());
    auto ptr = (uint8_t *)buf.ptr;
    return std::vector<uint8_t>(ptr, ptr + buf.len);
}  // CBOR::Decoder::getTaggedCborBytes

auto CBOR::Decoder::getRational() -> std::pair<uint64_t, uint64_t>
{
    auto itm = std::static_pointer_cast<QCBORItem>(this->_cbor_itm);
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_EnterArray(ctx.get(), itm.get());
    auto tag = QCBORDecode_GetNthTagOfLast(ctx.get(), 0);
    if ((tag != 30) || (itm->uDataType != QCBOR_TYPE_ARRAY) ||
        (ctx->uLastError != QCBOR_SUCCESS))
        std::runtime_error("Invalid rational number CBOR structure.");
    // The numerator can be a Uint, Int, or BigNum.
    // The denominator can be a Uint or positive BigNum (not equal to Zero!).
    // TODO: Handle non-Uint types.
    uint64_t num, den;
    QCBORDecode_GetUInt64(ctx.get(), &num);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Unexpected data type.");
    QCBORDecode_GetUInt64(ctx.get(), &den);
    if (ctx->uLastError != QCBOR_SUCCESS)
        throw std::invalid_argument("Unexpected data type.");
    QCBORDecode_ExitArray(ctx.get());
    return std::make_pair(num, den);
}  // CBOR::Decoder::getRational

auto CBOR::Decoder::keyInMap(int64_t k) -> bool
{
    QCBORItem item;
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    QCBORDecode_GetItemInMapN(ctx.get(), k, QCBOR_TYPE_ANY, &item);
    auto ret_val = (ctx->uLastError == QCBOR_SUCCESS);
    QCBORDecode_GetAndResetError(ctx.get());
    return ret_val;
}  // CBOR::Decoder::keyInMap

auto CBOR::Decoder::keyInMap(std::string_view k) -> bool
{
    QCBORItem item;
    auto ctx = std::static_pointer_cast<QCBORDecodeContext>(this->_cbor_ctx);
    auto kstr = std::string(k);  // Need NULL terminated string
    QCBORDecode_GetItemInMapSZ(ctx.get(), kstr.c_str(), QCBOR_TYPE_ANY, &item);
    auto ret_val = (ctx->uLastError == QCBOR_SUCCESS);
    QCBORDecode_GetAndResetError(ctx.get());
    return ret_val;
}  // CBOR::Decoder::keyInMap