// Copyright (c) 2025 Viper Science LLC
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

#include <cardano/cardano.hpp>

auto main() -> int
{
    constexpr auto root_prv_base16 = "5079457179b48efd3be6bfe351959c490df067defba703b5e8264ad7fc4b304c175f5a248c8762de70feae23b647b33f63ea478c16803eb7137afd194166eabf";
    constexpr auto root_pub_base16 = "e34ccf1393dc758f0042d9e9c0a7f7151e0f046e3ca1c6b0764475e1d03e0372";
    constexpr auto root_cc_base16 = "da644915ce8c9b7333b43a05d029064f570b2ff1d865165968e06f10cb4894d8";
    constexpr auto addr_0H0H_base58 = "DdzFFzCqrht4nJCMRgF8xpNMbHFj3xjZn6f4ngpnUujcNXpm5KQFYgU7jwj42ZyjNyjnUqq5ngfEH5YS6hpykqvE78BHTMvgauTBQdsb";

    auto root_xprv_enc = cardano::bip32_ed25519::EncryptedPrivateKey(
        cardano::util::makeByteArray<64>(cardano::BASE16::decode(root_prv_base16)),
        cardano::util::makeByteArray<32>(cardano::BASE16::decode(root_cc_base16))
    );
    auto root_xprv = root_xprv_enc.decrypt(R"(B1CD6Vv9$%@W5Vo%iR5$pv01)");
    auto addr_0H0H_from_str = cardano::ByronAddress::fromBase58(addr_0H0H_base58);
    auto derivation_path_0H0H = std::vector<uint32_t>{
        cardano::bip32_ed25519::HardenIndex(0),
        cardano::bip32_ed25519::HardenIndex(0)
    };
    auto addr_0H0H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H0H);

    // Return 0 for success
    return (int)(addr_0H0H_from_key.toBase58() != addr_0H0H_base58);
}