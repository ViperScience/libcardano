#include <cardano/encodings.hpp>
#include <cardano/vrf.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace cardano;

template <std::size_t Size>
static auto hexToByteArray(std::string_view hex) -> std::array<uint8_t, Size>
{
    auto bytes = BASE16::decode(hex);
    if (bytes.size() < Size) throw std::invalid_argument("Invalid hex string.");
    auto byte_array = std::array<uint8_t, Size>{};
    std::copy_n(bytes.begin(), Size, byte_array.begin());
    return byte_array;
}

TEST_CASE("testCardanoVRFAPI")
{
    typedef struct TestData_
    {
        const char seed[2 * 32 + 1];
        const char pubk[2 * 32 + 1];
        const char proof[2 * 80 + 1];
        const char hash[2 * 64 + 1];
    } TestData;

    /// Test data taken from
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03#appendix-A.4
    /// which contains the seeds and expected values.
    static const TestData test_data[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a"
         "126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe7"
         "01677c0f602900",
         "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec"
         "5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece"
         "87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717"
         "e895fd15f99f07",
         "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84"
         "991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976c"
         "fd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055"
         "b561ece45e1009",
         "2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a"
         "4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded"}
    };

    static const unsigned char messages[3][2] = {{0x00}, {0x72}, {0xaf, 0x82}};

    SECTION("testBasic")
    {
        const auto seed = hexToByteArray<32>(test_data[0].seed);
        auto vrf_key = VRFSecretKey::fromSeed(seed);
        auto proof = vrf_key.constructProof(messages[0]);
        auto vrf_pkey = vrf_key.publicKey();
        REQUIRE(vrf_pkey.verifyProof(messages[0], proof));
        REQUIRE(vrf_key.hash(messages[0]) == vrf_key.proofToHash(proof));
    }

    // This test is based on the test included in the Cardano fork of libsodium.
    SECTION("testAdvanced")
    {
        for (size_t i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++)
        {
            // Create the key pair from the seed.
            const auto seed = hexToByteArray<32>(test_data[i].seed);
            auto vrf_skey = VRFSecretKey::fromSeed(seed);

            auto vrf_pkey = vrf_skey.publicKey();
            REQUIRE(vrf_pkey.bytes() == hexToByteArray<32>(test_data[i].pubk));

            // Create the proof.
            auto proof = vrf_skey.constructProof({messages[i], i});
            REQUIRE(proof == hexToByteArray<80>(test_data[i].proof));

            // Verify the proof.
            REQUIRE(vrf_pkey.verifyProof({messages[i], i}, proof));

            // Check the proof hash.
            auto hash = vrf_skey.hash({messages[i], i});
            REQUIRE(hash == hexToByteArray<64>(test_data[i].hash));

            // Verify the proof does not work when the proof is modified.

            proof[0] ^= 0x01;  // bad gamma
            REQUIRE(!vrf_pkey.verifyProof({messages[i], i}, proof));
            proof[0] ^= 0x01;

            proof[32] ^= 0x01;  // bad c value
            REQUIRE(!vrf_pkey.verifyProof({messages[i], i}, proof));
            proof[32] ^= 0x01;

            proof[48] ^= 0x01;  // bad s value
            REQUIRE(!vrf_pkey.verifyProof({messages[i], i}, proof));
            proof[48] ^= 0x01;

            proof[79] ^= 0x80;  // bad s value (high-order-bit flipped)
            REQUIRE(!vrf_pkey.verifyProof({messages[i], i}, proof));
            proof[79] ^= 0x80;

            if (i > 0)
            {
                // Verify should fail with truncated message.
                REQUIRE(!vrf_pkey.verifyProof({messages[i], i - 1}, proof));
            }
        }
    }
}