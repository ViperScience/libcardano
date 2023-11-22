#include <cardano/encodings.hpp>
#include <cardano/stake_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <streambuf>
#include <string>

using namespace cardano;

constexpr auto VKEY_BECH32 =
    "pool_vk1055etzd6e8e84hpc2vlwu907dqcrlg4mqvkjczs8e0usmptgm8tqw2g8ry";
constexpr auto SKEY_BECH32 =
    "pool_sk14q89yhfgvgk7xyfcc4sacunfj2tt88a3q83wt73p0lmp2y3cnj6se3l07g";
constexpr auto POOL_BECH32 =
    "pool16r8fhvl4y9y9n2qe9spq0hfyjv4th3crg2k072etym30y638el4";
constexpr auto KEY_FILE_PATH = "test.skey";
constexpr auto KEY_FILE_CONTENTS = R"({
    "type": "StakePoolSigningKey_ed25519",
    "description": "Stake Pool Operator Signing Key",
    "cborHex": "5820a80e525d28622de31138c561dc72699296b39fb101e2e5fa217ff61512389cb5"
})";
constexpr auto EXT_KEY_FILE_CONTENTS = R"({
    "type": "StakePoolExtendedSigningKey_ed25519_bip32",
    "description": "Stake Pool Operator Signing Key",
    "cborHex": "5840d8f4f198623d9617528d06999fdf3837cb965ad8ca3fe50424816e1a6add814f4183bbc9ab268a9026b2ee0db94cb0d8540ea19e0c6a85543d2b64d76dea1d68"
})";
constexpr auto POOL_KEY_MNEMONIC =
    "man tattoo narrow exhaust twist quiz sand horse easily rack theory animal "
    "rack lens final priority horror step metal song humor small setup curious";

TEST_CASE(
    "Verify basic stake pool cold key functionality.", "[stake_pool_cold_key]"
)
{
    auto [vhrp, vkey_bytes] = BECH32::decode(VKEY_BECH32);
    auto [shrp, skey_bytes] = BECH32::decode(SKEY_BECH32);

    auto vkey = stake_pool::ColdVerificationKey(vkey_bytes);
    auto skey = stake_pool::ColdSigningKey(skey_bytes);
    auto ext_skey = skey.extend();

    REQUIRE(vkey.asBech32() == VKEY_BECH32);
    REQUIRE(skey.asBech32() == SKEY_BECH32);
    REQUIRE(skey.verificationKey().asBech32() == VKEY_BECH32);
    REQUIRE(vkey.asBech32() == ext_skey.verificationKey().asBech32());

    SECTION("test exporting keys to file")
    {
        skey.saveToFile(KEY_FILE_PATH);
        auto key_file = std::ifstream(KEY_FILE_PATH);
        auto key_file_str = std::string(
            (std::istreambuf_iterator<char>(key_file)),
            std::istreambuf_iterator<char>()
        );
        key_file.close();

        REQUIRE(key_file_str == KEY_FILE_CONTENTS);

        ext_skey.saveToFile(KEY_FILE_PATH);
        key_file = std::ifstream(KEY_FILE_PATH);
        key_file_str = std::string(
            (std::istreambuf_iterator<char>(key_file)),
            std::istreambuf_iterator<char>()
        );
        key_file.close();

        REQUIRE(key_file_str == EXT_KEY_FILE_CONTENTS);
    }

    SECTION("pool id verification ")
    {
        const auto pool_id_bytes = vkey.poolId();
        REQUIRE(BECH32::encode("pool", pool_id_bytes) == POOL_BECH32);
        REQUIRE(skey.poolId() == pool_id_bytes);
        REQUIRE(ext_skey.poolId() == pool_id_bytes);
    }
}

TEST_CASE("Verify stake pool CIP-1853 functionality.", "[stake_pool_cold_key]")
{
    auto mn = Mnemonic(POOL_KEY_MNEMONIC, BIP39Language::English);

    SECTION("Key derivation (CIP-1853)")
    {
        auto root_xsk = BIP32PrivateKey::fromMnemonic(mn);
        auto cold_skey1 = stake_pool::ExtendedColdSigningKey::fromMnemonic(mn);
        auto cold_skey2 =
            stake_pool::ExtendedColdSigningKey::fromRootKey(root_xsk);

        REQUIRE(cold_skey1.bytes() == cold_skey2.bytes());
    }

    SECTION("Generate extended cold key from RNG")
    {
        auto cold_key = stake_pool::ExtendedColdSigningKey::generate();
        auto key = ed25519::ExtendedPrivateKey{cold_key.bytes()};
        REQUIRE(key.isValid());
    }
}