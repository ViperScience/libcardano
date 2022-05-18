#include <string>

#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>
#include <cardano/mnemonic.hpp>
#include <test/tests.hpp>

auto testBasic() -> void {
    for (const auto sz : {9, 12, 15, 18, 21, 24}) {
        for (size_t n = 0; n < 1000; ++n) {
            auto mn = cardano::Mnemonic::generate(sz);
            TEST_ASSERT_THROW( mn.size() == sz )
            TEST_ASSERT_THROW( mn.verify_checksum() )
        }
    }
}

auto testIntermediate() -> void {
    // This is an English recovery phrase, ordered left-to-right, then top-to-bottom.
    //
    // write       maid        rib
    // female      drama       awake
    // release     inhale      weapon
    // crush       mule        jump
    // sound       erupt       stereo
    //
    // It is 15 words long, so 15*11=165 bits of information, which is split into a 160 bit seed and 5 bit checksum.
    //
    // Using the dictionary, these words resolve to:
    //
    // 2036        1072        1479
    // 679         529         129
    // 1449        925         1986
    // 424         1162        967
    // 1662        615         1708
    //
    // Which is:
    //
    // Seed:
    // 11111110100 10000110000 10111000111
    // 01010100111 01000010001 00010000001
    // 10110101001 01110011101 11111000010
    // 00110101000 10010001010 01111000111
    // 11001111110 01001100111 110101
    // Checksum:                     01100
    //
    // Seed (base16):     fe90c2e3aa7422206d4b9df846a2453c7cfc99f5
    // Checksum (base16): 0c
    constexpr std::string_view seed_phrase = "write maid rib female drama awake release inhale weapon crush mule jump sound erupt stereo";
    constexpr std::array<uint16_t, 15> dictionary_indexes = {
        2036, 1072, 1479, 679, 529, 129, 1449, 925, 1986, 424, 1162, 967, 1662,
        615, 1708
    };
    constexpr std::array<uint8_t, 20> seed = {
        0b11111110, 0b10010000, 0b11000010, 0b11100011, 0b10101010,
        0b01110100, 0b00100010, 0b00100000, 0b01101101, 0b01001011,
        0b10011101, 0b11111000, 0b01000110, 0b10100010, 0b01000101,
        0b00111100, 0b01111100, 0b11111100, 0b10011001, 0b11110101
    };
    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);
    auto mn_idxs = mn.i();
    for (auto i = 0ul; i < dictionary_indexes.size(); i++) {
        TEST_ASSERT_THROW( dictionary_indexes[i] == mn_idxs[i] )
    }
    TEST_ASSERT_THROW( mn.checksum() == 0x0c )
    TEST_ASSERT_THROW( mn.verify_checksum() )
    auto mn_seed = mn.toSeed();
    for (auto i = 0ul; i < seed.size(); i++) {
        TEST_ASSERT_THROW( seed[i] == mn_seed[i] )
    }
}

auto testAdvanced() -> void {
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    
    constexpr std::string_view root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    constexpr std::string_view addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc";
    constexpr std::string_view stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve";
    constexpr std::string_view byron_root_xsk_bech32 = "root_xsk1jp7kf6u54cghedhx9mlfzpggvkqz0gne8uulydw6e5n6cdzawa8ntz2fmzwatct2az90ns2eczdsn359k438skraqyww30rcw768mkwlutncnk4cluupgaqu5u02wepn7kqdvgfghq4anl9cl3rkzxl4uughzf0v";
    
    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

    // Test the Byron root key derivation.
    auto root_xsk_byron = cardano::BIP32PrivateKey::fromMnemonicByron(mn);
    TEST_ASSERT_THROW( root_xsk_byron.toBech32("root_xsk") == byron_root_xsk_bech32 )

    // Test the Shelley root key derivation.
    auto root_xsk = cardano::BIP32PrivateKey::fromMnemonic(mn);
    TEST_ASSERT_THROW( root_xsk.toBech32("root_xsk") == root_xsk_bech32 )

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

auto main() -> int {
  testBasic();
  testIntermediate();
  testAdvanced();
  return 0;
}