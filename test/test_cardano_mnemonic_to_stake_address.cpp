#include <string_view>

#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/mnemonic.hpp>
#include <test/tests.hpp>

auto main() -> int
{
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    
    constexpr std::string_view root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    constexpr std::string_view stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve";
    constexpr std::string_view stake_addr_bech32 = "stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat";

    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

    // Test the Shelley root key derivation.
    auto root_xsk = cardano::BIP32PrivateKey::fromMnemonic(mn);
    TEST_ASSERT_THROW( root_xsk.toBech32("root_xsk") == root_xsk_bech32 )

    // Derive the stake key from the root
    auto acct_xsk = root_xsk.deriveChild(cardano::HardenIndex(1852))
                            .deriveChild(cardano::HardenIndex(1815))
                            .deriveChild(cardano::HardenIndex(0));
    auto acct_xvk = acct_xsk.toPublic();
    auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);
    TEST_ASSERT_THROW( stake_xvk.toBech32("stake_xvk") == stake_xvk_bech32 )

    // Derive the stake address
    auto stake_addr = cardano::RewardsAddress::fromKey(cardano::NetworkID::testnet, stake_xvk);
    TEST_ASSERT_THROW( stake_addr.toBech32("stake_test") == stake_addr_bech32 )

    return 0;
}