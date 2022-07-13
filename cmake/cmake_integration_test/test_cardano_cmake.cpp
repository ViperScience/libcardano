#include <string>
#include <iostream>
#include <cardano/cardano.hpp>
auto main() -> int
{
    std::string root_prv_base16 = "5079457179b48efd3be6bfe351959c490df067defba703b5e8264ad7fc4b304c175f5a248c8762de70feae23b647b33f63ea478c16803eb7137afd194166eabf";
    std::string root_pub_base16 = "e34ccf1393dc758f0042d9e9c0a7f7151e0f046e3ca1c6b0764475e1d03e0372";
    std::string root_cc_base16 = "da644915ce8c9b7333b43a05d029064f570b2ff1d865165968e06f10cb4894d8";
    std::string addr_0H0H_base58 = "DdzFFzCqrht4nJCMRgF8xpNMbHFj3xjZn6f4ngpnUujcNXpm5KQFYgU7jwj42ZyjNyjnUqq5ngfEH5YS6hpykqvE78BHTMvgauTBQdsb";

    auto root_xprv_enc = cardano::BIP32PrivateKeyEncrypted(root_prv_base16, root_cc_base16);
    auto root_xprv = root_xprv_enc.decrypt(R"(B1CD6Vv9$%@W5Vo%iR5$pv01)");
    auto addr_0H0H_from_str = cardano::ByronAddress::fromBase58(addr_0H0H_base58);
    auto derivation_path_0H0H = std::vector<uint32_t>{cardano::HardenIndex(0), cardano::HardenIndex(0)};
    auto addr_0H0H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H0H);

    std::cout << "Hello World!" << std::endl;

    // Return 0 for success
    return (int)(addr_0H0H_from_key.toBase58() != addr_0H0H_base58);
}