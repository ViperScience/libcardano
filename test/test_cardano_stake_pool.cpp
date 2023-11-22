#include <cardano/encodings.hpp>
#include <cardano/stake_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <streambuf>
#include <string>

using namespace cardano;

constexpr auto VKEY_BECH32 = "pool_vk1055etzd6e8e84hpc2vlwu907dqcrlg4mqvkjczs8e0usmptgm8tqw2g8ry";
constexpr auto SKEY_BECH32 = "pool_sk14q89yhfgvgk7xyfcc4sacunfj2tt88a3q83wt73p0lmp2y3cnj6se3l07g";
constexpr auto POOL_BECH32 = "pool16r8fhvl4y9y9n2qe9spq0hfyjv4th3crg2k072etym30y638el4";
constexpr auto KEY_FILE_PATH = "test.skey";
constexpr auto KEY_FILE_CONTENTS = R"({
    "type": "StakePoolSigningKey_ed25519",
    "description": "Stake Pool Operator Signing Key",
    "cborHex": "5820a80e525d28622de31138c561dc72699296b39fb101e2e5fa217ff61512389cb5"
})";

TEST_CASE( "Verify stake pool functionality.", "[stake_pool]" )
{
    auto [vhrp, vkey_bytes] = BECH32::decode(VKEY_BECH32);
    auto [shrp, skey_bytes] = BECH32::decode(SKEY_BECH32);

    auto vkey = stake_pool::ColdVerificationKey(vkey_bytes);
    auto skey = stake_pool::ColdSigningKey(skey_bytes);
    auto ext_skey = skey.extend();

    REQUIRE( vkey.asBech32() == VKEY_BECH32 );
    REQUIRE( skey.asBech32() == SKEY_BECH32 );
    REQUIRE( skey.verificationKey().asBech32() == VKEY_BECH32 );
    REQUIRE( vkey.asBech32() == ext_skey.verificationKey().asBech32() );

    SECTION( "test exporting keys to file" ) 
    {
        skey.saveToFile(KEY_FILE_PATH);
        std::ifstream key_file(KEY_FILE_PATH);
        std::string key_file_str(
            (std::istreambuf_iterator<char>(key_file)),
            std::istreambuf_iterator<char>()
        );

        REQUIRE( key_file_str == KEY_FILE_CONTENTS );
    }   

    SECTION( "pool id verification ")
    {
        const auto pool_id_bytes = vkey.poolId();
        REQUIRE( BECH32::encode("pool", pool_id_bytes) == POOL_BECH32 );
        REQUIRE( skey.poolId() == pool_id_bytes );
        REQUIRE( ext_skey.poolId() == pool_id_bytes );
    }
}