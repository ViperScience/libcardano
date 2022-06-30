#include <string>

#include <cardano/mnemonic.hpp>
#include <test/tests.hpp>

auto testBasic() -> void
{
    for (const auto sz : {9, 12, 15, 18, 21, 24})
    {
        for (size_t n = 0; n < 1000; ++n)
        {
            auto mn = cardano::Mnemonic::generate(sz);
            TEST_ASSERT_THROW( mn.size() == sz )
            TEST_ASSERT_THROW( mn.verify_checksum() )
        }
    }
}

auto testAdvanced() -> void
{
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
    for (auto i = 0ul; i < dictionary_indexes.size(); i++)
        TEST_ASSERT_THROW( dictionary_indexes[i] == mn_idxs[i] )

    TEST_ASSERT_THROW( mn.checksum() == 0x0c )
    TEST_ASSERT_THROW( mn.verify_checksum() )
    auto mn_seed = mn.toSeed();
    for (auto i = 0ul; i < seed.size(); i++)
        TEST_ASSERT_THROW( seed[i] == mn_seed[i] )
}

auto main() -> int
{
    testBasic();
    testAdvanced();
    return 0;
}