#include <iostream>
#include <string>

#include <test/tests.hpp>
#include <cardano/encodings.hpp>

void testBech32Basic() {
    std::string addr_bech32 = "addr1qyghraqad85ue38enxtdkmfsmxktds58msuxhqwyq87yjd2pefk9uwxnjt63hj85l8srdgfh50y7repx0ymaspz5s3msgdc7y8";
    std::string addr_hex = "011171f41d69e9ccc4f99996db6d30d9acb6c287dc386b81c401fc493541ca6c5e38d392f51bc8f4f9e036a137a3c9e1e4267937d804548477";

    auto [ hrp, data ] = cardano::BECH32::decode_hex(addr_bech32);
    TEST_ASSERT_THROW( hrp == "addr" );
    TEST_ASSERT_THROW( data == addr_hex );

    auto data_bech32 = cardano::BECH32::encode_hex("addr", data);
    TEST_ASSERT_THROW( data_bech32 == addr_bech32 );
}

void testBech32Advanced() {
    std::string pool_id_hex = "d69b6b16c6a135c4157365ded9b0d772d44c7628a05b49741d3ae25c";
    std::string pool_id_bech32 = "pool166dkk9kx5y6ug9tnvh0dnvxhwt2yca3g5pd5jaqa8t39cgyqqlr";
    std::string stake_hex = "e130188f574458076f6746c4d0b7904247dd477db7d0be91fc919eedfe"; // e1 -> header byte
    std::string stake_bech32 = "stake1uycp3r6hg3vqwmm8gmzdpdusgfra63maklgtay0ujx0wmlstrah3d";

    auto [ hrp1, data1 ] = cardano::BECH32::decode_hex(pool_id_bech32);
    TEST_ASSERT_THROW( hrp1 == "pool" );
    TEST_ASSERT_THROW( data1 == pool_id_hex );

    auto data1_bech32 = cardano::BECH32::encode_hex("pool", pool_id_hex);
    TEST_ASSERT_THROW( data1_bech32 == pool_id_bech32 );

    auto [ hrp2, data2 ] = cardano::BECH32::decode_hex(stake_bech32);
    TEST_ASSERT_THROW( hrp2 == "stake" );
    TEST_ASSERT_THROW( data2 == stake_hex );

    auto data2_bech32 = cardano::BECH32::encode_hex("stake", stake_hex);
    TEST_ASSERT_THROW( data2_bech32 == stake_bech32 );
}

void testBase58() {
  std::vector<uint8_t> v1{0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd};
  std::string v1_b58 = "11233QC4";
  std::string addr_hex = "82d818584283581c34c964f2ba4bc1ad09e131f110ff5bb835110069967ca0f62e0c39f1a101581e581ce07c1b3a70256505b286ba878318800b1b980a83fd5a1ec63f247b13001a6dfc0e16";
  std::string addr_b58 = "DdzFFzCqrhskgmnxD51DjjQajd4Q7mhNaHjSXMi6Cg77VbwWgdCgT8X2zYtTfszqKB2XKR7dhgSBfsgJfzmmAYGtKcHKYqKhWy7o9fwb";
  
  auto v1_encoding = cardano::BASE58::encode(v1);
  TEST_ASSERT_THROW(v1_encoding == v1_b58);

  auto addr_encoding = cardano::BASE58::encode_hex(addr_hex);
  TEST_ASSERT_THROW(addr_encoding == addr_b58);

  auto v1_decode = cardano::BASE58::decode(v1_b58);
  TEST_ASSERT_THROW(v1_decode == v1);

  auto addr_decode = cardano::BASE58::decode_hex(addr_b58);
  TEST_ASSERT_THROW(addr_decode == addr_hex);
}

int main(int, char**) {
  testBech32Basic();
  testBech32Advanced();
  testBase58();
  return 0;
}