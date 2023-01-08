#include <string>
#include <test/tests.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

auto testBasic() -> void
{
    std::string root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    std::string addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc";
    std::string stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve";

    auto root_xsk = cardano::BIP32PrivateKey::fromBech32(root_xsk_bech32);
    auto acct_xsk = root_xsk.deriveChild(cardano::HardenIndex(1852))
                            .deriveChild(cardano::HardenIndex(1815))
                            .deriveChild(cardano::HardenIndex(0));
    auto acct_xvk = acct_xsk.toPublic();
    auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
    auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

    TEST_ASSERT_THROW( root_xsk.toBech32("root_xsk") == root_xsk_bech32 )
    TEST_ASSERT_THROW( addr_xvk.toBech32("addr_xvk") == addr_xvk_bech32 )
    TEST_ASSERT_THROW( stake_xvk.toBech32("stake_xvk") == stake_xvk_bech32 )
}

auto testAdvanced() -> void
{
    std::string root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    std::string root_xsk_base16 = "b804910d10b2261742c630d94b5e1ecc2075670438ba5fd329f65fd4b547a943110c92c9f17b44b332d9d7c1cea6f3108ad99546c6d31dcc41161f3cf529a9e82d186a96f0f3823e498778084c6625a413454424114e532c84d760201df08cdb";
    std::string addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc";
    std::string stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve";
    std::string stake_xvk_base16 = "d50fd5896be4fbb14cef53eb6b8d0f025b6a4d9b1f17fdec28f1bf027508777d728ab0def208321af02e406f0af83af6123a1a55fefaa4d9fb4096220d40b0f0";
    std::string zeros_base16 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    std::string password = "password";

    auto root_xsk = cardano::BIP32PrivateKey::fromBech32(root_xsk_bech32);
    auto root_xsk_v2 = cardano::BIP32PrivateKey::fromBytes(cardano::BASE16::decode(root_xsk_base16));
    TEST_ASSERT_THROW( root_xsk.toBase16() == root_xsk_v2.toBase16() )

    auto root_xsk_enc = root_xsk.encrypt(password);
    auto acct_xsk_enc = root_xsk_enc.deriveChild(cardano::HardenIndex(1852), password)
                                    .deriveChild(cardano::HardenIndex(1815), password)
                                    .deriveChild(cardano::HardenIndex(0), password);
    auto acct_xvk = acct_xsk_enc.toPublic("password");
    auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
    auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

    TEST_ASSERT_THROW( root_xsk_enc.decrypt(password).toBech32("root_xsk") == root_xsk_bech32 )
    TEST_ASSERT_THROW( addr_xvk.toBech32("addr_xvk") == addr_xvk_bech32 )
    TEST_ASSERT_THROW( stake_xvk.toBech32("stake_xvk") == stake_xvk_bech32 )

    TEST_ASSERT_THROW( stake_xvk.toBase16() == stake_xvk_base16 )
    TEST_ASSERT_THROW( root_xsk_enc.decrypt(password).toBase16() == root_xsk_base16 )

    TEST_ASSERT_THROW( addr_xvk.toCBOR() == "5840" + addr_xvk.toBase16() )
    TEST_ASSERT_THROW( addr_xvk.toCBOR(false) == "5820" + addr_xvk.toBase16().substr(0, 64) )
    TEST_ASSERT_THROW( stake_xvk.toCBOR() == "5840" + stake_xvk.toBase16() )
    TEST_ASSERT_THROW( stake_xvk.toCBOR() == "5840" + stake_xvk_base16 )
    TEST_ASSERT_THROW( root_xsk_enc.decrypt(password).toCBOR() == "5860" + root_xsk_base16 )
}

auto main() -> int
{
    testBasic();
    testAdvanced();
    return 0;
}