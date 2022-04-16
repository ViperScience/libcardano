#include <string>

#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>
#include <src/debug_utils.hpp>
#include <test/tests.hpp>

void testBasic() {
    // The tests setup here verify the data supplied in the Cardano documentation at:
    // https://input-output-hk.github.io/cardano-wallet/concepts/byron-address-format

    std::string yoroi_base58 = "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi";
    std::vector<uint8_t> yoroi_cbor = {
        0x82, 0xD8, 0x18, 0x58, 0x21, 0x83, 0x58, 0x1C, 0xBA, 0x97, 0x0A, 0xD3, 0x66, 0x54, 0xD8,
        0xDD, 0x8F, 0x74, 0x27, 0x4B, 0x73, 0x34, 0x52, 0xDD, 0xEA, 0xB9, 0xA6, 0x2A, 0x39, 0x77,
        0x46, 0xBE, 0x3C, 0x42, 0xCC, 0xDD, 0xA0, 0x00, 0x1A, 0x90, 0x26, 0xDA, 0x5B
    };
    auto yoroi_addr_from_str = cardano::ByronAddress::fromBase58(yoroi_base58);
    auto yoroi_addr_from_cbor = cardano::ByronAddress::fromCBOR(yoroi_cbor);
    TEST_ASSERT_THROW( yoroi_addr_from_str.toBase58() == yoroi_base58 )
    TEST_ASSERT_THROW( yoroi_addr_from_cbor.toBase58() == yoroi_base58 )

    std::string addr_base58 = "37btjrVyb4KEB2STADSsj3MYSAdj52X5FrFWpw2r7Wmj2GDzXjFRsHWuZqrw7zSkwopv8Ci3VWeg6bisU9dgJxW5hb2MZYeduNKbQJrqz3zVBsu9nT";
    std::vector<uint8_t> addr_cbor = {
        0x82, 0xD8, 0x18, 0x58, 0x49, 0x83, 0x58, 0x1C, 0x9C, 0x70, 0x85, 0x38, 0xA7, 0x63, 0xFF,
        0x27, 0x16, 0x99, 0x87, 0xA4, 0x89, 0xE3, 0x50, 0x57, 0xEF, 0x3C, 0xD3, 0x77, 0x8C, 0x05,
        0xE9, 0x6F, 0x7B, 0xA9, 0x45, 0x0E, 0xA2, 0x01, 0x58, 0x1E, 0x58, 0x1C, 0x9C, 0x17, 0x22,
        0xF7, 0xE4, 0x46, 0x68, 0x92, 0x56, 0xE1, 0xA3, 0x02, 0x60, 0xF3, 0x51, 0x0D, 0x55, 0x8D,
        0x99, 0xD0, 0xC3, 0x91, 0xF2, 0xBA, 0x89, 0xCB, 0x69, 0x77, 0x02, 0x45, 0x1A, 0x41, 0x70,
        0xCB, 0x17, 0x00, 0x1A, 0x69, 0x79, 0x12, 0x6C
    };
    auto addr_from_str = cardano::ByronAddress::fromBase58(addr_base58);
    auto addr_from_cbor = cardano::ByronAddress::fromCBOR(addr_cbor);
    TEST_ASSERT_THROW( addr_from_str.toBase58() == addr_base58 )
    TEST_ASSERT_THROW( addr_from_cbor.toBase58() == addr_base58 )
}

void testAdvanced() {
    std::string root_prv_base16 = "5079457179b48efd3be6bfe351959c490df067defba703b5e8264ad7fc4b304c175f5a248c8762de70feae23b647b33f63ea478c16803eb7137afd194166eabf";
    std::string root_pub_base16 = "e34ccf1393dc758f0042d9e9c0a7f7151e0f046e3ca1c6b0764475e1d03e0372";
    std::string root_cc_base16 = "da644915ce8c9b7333b43a05d029064f570b2ff1d865165968e06f10cb4894d8";
    std::string addr_0H0H_base58 = "DdzFFzCqrht4nJCMRgF8xpNMbHFj3xjZn6f4ngpnUujcNXpm5KQFYgU7jwj42ZyjNyjnUqq5ngfEH5YS6hpykqvE78BHTMvgauTBQdsb";
    std::string addr_0H869280224H_base58 = "DdzFFzCqrhsw7KpiDuCQfhf6szHmZqqZRUrPEkj8ij7yx2ahM3jh1LAFYjTmqCGuTp6BVqPbAfddHGwAinLNtyPmojLe1jx3UU6vzqKc";
    std::string addr_0H2071358278H_base58 = "DdzFFzCqrhsemgxPDQLmn6auZnUbzaxeEj6FLZuwAP5pK6WrCandFPhcGGrc5h5LR8zz67YHfiCnKsLFFgSbDtfN93guwXxYTrS5XEYd";
    std::string addr_0H2075417326H_base58 = "DdzFFzCqrhsjUUQkiBpCSYkWLtJPmrPKjg2RPK6hRTgyejsraJh2HKQcHwdDdBHpNCvNLj2PxBrUGMxyvuQtULKv7yLzfmfEo5S5vx8z";
    std::string addr_0H492230898H_base58 = "DdzFFzCqrht7XNfGYnNyan5fKfLQWs8KVUZ9Jab65r87cvs2vyJ4n9gaCPUGdHMzSA8qKo8x6E76Di4xQQukcVdtaSmwpVkv5ZiUmJa3";

    auto root_xprv_enc = cardano::BIP32PrivateKeyEncrypted(root_prv_base16, root_cc_base16);
    auto root_xprv = root_xprv_enc.decrypt(R"(B1CD6Vv9$%@W5Vo%iR5$pv01)");
    TEST_ASSERT_THROW( root_xprv.toPublic().toBase16() == root_pub_base16 + root_cc_base16 )

    auto addr_0H0H_from_str = cardano::ByronAddress::fromBase58(addr_0H0H_base58);
    auto addr_0H869280224H_from_str = cardano::ByronAddress::fromBase58(addr_0H869280224H_base58);
    auto addr_0H2071358278H_from_str = cardano::ByronAddress::fromBase58(addr_0H2071358278H_base58);
    auto addr_0H2075417326H_from_str = cardano::ByronAddress::fromBase58(addr_0H2075417326H_base58);
    auto addr_0H492230898H_from_str = cardano::ByronAddress::fromBase58(addr_0H492230898H_base58);

    TEST_ASSERT_THROW( addr_0H0H_from_str.toBase58() == addr_0H0H_base58 )
    TEST_ASSERT_THROW( addr_0H869280224H_from_str.toBase58() == addr_0H869280224H_base58 )
    TEST_ASSERT_THROW( addr_0H2071358278H_from_str.toBase58() == addr_0H2071358278H_base58 )
    TEST_ASSERT_THROW( addr_0H2075417326H_from_str.toBase58() == addr_0H2075417326H_base58 )
    TEST_ASSERT_THROW( addr_0H492230898H_from_str.toBase58() == addr_0H492230898H_base58 )

    auto derivation_path_0H0H = std::vector<uint32_t>{cardano::HardenIndex(0), cardano::HardenIndex(0)};
    auto derivation_path_0H869280224H = std::vector<uint32_t>{cardano::HardenIndex(0), cardano::HardenIndex(869280224)};
    auto derivation_path_0H2071358278H = std::vector<uint32_t>{cardano::HardenIndex(0), cardano::HardenIndex(2071358278)};
    auto derivation_path_0H2075417326H = std::vector<uint32_t>{cardano::HardenIndex(0), cardano::HardenIndex(2075417326)};
    auto derivation_path_0H492230898H = std::vector<uint32_t>{cardano::HardenIndex(0), cardano::HardenIndex(492230898)};

    auto addr_0H0H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H0H);
    auto addr_0H869280224H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H869280224H);
    auto addr_0H2071358278H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H2071358278H);
    auto addr_0H2075417326H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H2075417326H);
    auto addr_0H492230898H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H492230898H);

    TEST_ASSERT_THROW( addr_0H0H_from_key.toBase58() == addr_0H0H_base58 )
    TEST_ASSERT_THROW( addr_0H869280224H_from_key.toBase58() == addr_0H869280224H_base58 )
    TEST_ASSERT_THROW( addr_0H2071358278H_from_key.toBase58() == addr_0H2071358278H_base58 )
    TEST_ASSERT_THROW( addr_0H2075417326H_from_key.toBase58() == addr_0H2075417326H_base58 )
    TEST_ASSERT_THROW( addr_0H492230898H_from_key.toBase58() == addr_0H492230898H_base58 )
}

int main() {
  testBasic();
  testAdvanced();
  return 0;
}