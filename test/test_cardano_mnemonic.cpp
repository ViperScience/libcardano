#include <string>

#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>
#include <cardano/mnemonic.hpp>
#include <src/debug_utils.hpp>
#include <test/tests.hpp>

void testBasic() {
    for (const auto sz : {9, 12, 15, 18, 21, 24}) {
        for (size_t n = 0; n < 1000; ++n) {
            auto mn = cardano::Mnemonic::generate(sz);
            TEST_ASSERT_THROW( mn.size() == sz )
            TEST_ASSERT_THROW( mn.verify_checksum() )
        }
    }
}

void testAdvanced() {
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";
    constexpr std::string_view root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    constexpr std::string_view addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc";
    constexpr std::string_view stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve";

    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);
    // auto root_xsk = cardano::BIP32PrivateKey::fromMnemonic(mn);
    // auto root_xsk = cardano::BIP32PrivateKey::fromBech32(root_xsk_bech32);
    // auto acct_xsk = root_xsk.deriveChild(cardano::HardenIndex(1852))
    //                         .deriveChild(cardano::HardenIndex(1815))
    //                         .deriveChild(cardano::HardenIndex(0));
    // auto acct_xvk = acct_xsk.toPublic();
    // auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
    // auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

    // TEST_ASSERT_THROW( root_xsk.toBech32("root_xsk") == root_xsk_bech32 )
    // TEST_ASSERT_THROW( addr_xvk.toBech32("addr_xvk") == addr_xvk_bech32 )
    // TEST_ASSERT_THROW( stake_xvk.toBech32("stake_xvk") == stake_xvk_bech32 )
}

int main() {
  testBasic();
  testAdvanced();
  return 0;
}