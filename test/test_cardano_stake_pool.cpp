#include <cardano/encodings.hpp>
#include <cardano/stake_pool.hpp>
#include <string>
#include <test/tests.hpp>

using namespace cardano;

auto testBasic() -> void
{
    constexpr auto vkey_bech32 = "pool_vk1055etzd6e8e84hpc2vlwu907dqcrlg4mqvkjczs8e0usmptgm8tqw2g8ry";
    constexpr auto skey_bech32 = "pool_sk14q89yhfgvgk7xyfcc4sacunfj2tt88a3q83wt73p0lmp2y3cnj6se3l07g";
    constexpr auto pool_bech32 = "pool16r8fhvl4y9y9n2qe9spq0hfyjv4th3crg2k072etym30y638el4";

    auto [vhrp, vkey_bytes] = BECH32::decode(vkey_bech32);
    auto [shrp, skey_bytes] = BECH32::decode(skey_bech32);

    auto vkey = stake_pool::ColdVerificationKey(vkey_bytes);
    auto skey = stake_pool::ColdSigningKey(skey_bytes);
    
    TEST_ASSERT_THROW(vkey.asBech32() == vkey_bech32)
    TEST_ASSERT_THROW(skey.asBech32() == skey_bech32)
    TEST_ASSERT_THROW(skey.verificationKey().bytes() == vkey.bytes())
    TEST_ASSERT_THROW(BECH32::encode("pool", vkey.poolId()) == pool_bech32)
}

auto testAdvanced() -> void
{
    const auto skey1 = stake_pool::ExtendedColdSigningKey::generate();
    skey1.saveToFile("test.skey");
}

auto main() -> int
{
    testBasic();
    testAdvanced();
    return 0;
}