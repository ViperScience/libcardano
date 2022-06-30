#include <string_view>

#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/mnemonic.hpp>
#include <test/tests.hpp>

auto main() -> int
{
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    
    constexpr std::string_view root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    constexpr std::string_view addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc";
    constexpr std::string_view base_addr_bech32 = "addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n";
    constexpr std::string_view payment_addr_bech32 = "addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v";

    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

    // Test the Shelley root key derivation.
    auto root_xsk = cardano::BIP32PrivateKey::fromMnemonic(mn);
    TEST_ASSERT_THROW( root_xsk.toBech32("root_xsk") == root_xsk_bech32 )

    // Derive the stake key from the root
    auto acct_xsk = root_xsk.deriveChild(cardano::HardenIndex(1852))
                            .deriveChild(cardano::HardenIndex(1815))
                            .deriveChild(cardano::HardenIndex(0));
    auto acct_xvk = acct_xsk.toPublic();
    auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
    auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);
    TEST_ASSERT_THROW( addr_xvk.toBech32("addr_xvk") == addr_xvk_bech32 )

    // Derive the enterprise address
    auto pmt_addr = cardano::EnterpriseAddress::fromKey(cardano::NetworkID::testnet, addr_xvk);
    TEST_ASSERT_THROW( pmt_addr.toBech32("addr_test") == payment_addr_bech32 )

    // Derive the base address
    auto addr = cardano::BaseAddress::fromKeys(cardano::NetworkID::testnet, addr_xvk, stake_xvk);
    TEST_ASSERT_THROW( addr.toBech32("addr_test") == base_addr_bech32 )

    return 0;
}