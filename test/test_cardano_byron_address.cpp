#include <iostream>
#include <string>

#include <test/tests.hpp>
#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

void testBasic() {

    //std::string yoroi_base58 = "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi";
    //auto yoroi_addr = cardano::ByronAddress::fromBase58(yoroi_base58);
    //TEST_ASSERT_THROW( yoroi_addr.toBase58() == yoroi_base58 )

    //std::string addr_base58 = "DdzFFzCqrhsrcTVhLygT24QwTnNqQqQ8mZrq5jykUzMveU26sxaH529kMpo7VhPrt5pwW3dXeB2k3EEvKcNBRmzCfcQ7dTkyGzTs658C";
    std::string addr_base58 = "37btjrVyb4KEB2STADSsj3MYSAdj52X5FrFWpw2r7Wmj2GDzXjFRsHWuZqrw7zSkwopv8Ci3VWeg6bisU9dgJxW5hb2MZYeduNKbQJrqz3zVBsu9nT";
    auto addr = cardano::ByronAddress::fromBase58(addr_base58);

    // for (auto val : addr.root()) {
    //     std::cout << "0x" << std::hex << int(val) << std::endl;
    // }

    // std::cout << addr.j.dump(4) << std::endl;
    // std::cout << addr.j["/0"_json_pointer].dump(4) << std::endl;
    // std::cout << addr.j["/1"_json_pointer].dump(4) << std::endl;
    // // std::cout << addr.j["/0"_json_pointer]["bytes"].get_binary().dump(4) << std::endl;
    
    // //// works...
    // auto crc = addr.j["/1"_json_pointer].get<uint32_t>();
    // std::cout << "CRC = " << std::dec << crc << std::endl;
    // ////

    // auto payload = addr.j["/0"_json_pointer].get_binary();
    // // for (auto val : payload) {
    // //     std::cout << "0x" << std::hex << int(val) << std::endl;
    // // }
    // // for (int i = 0; i < payload.size(); ++i) {
    // //     std::cout << std::dec << i << " 0x" << std::hex << int(payload[i]) << std::endl;
    // // }
    // for (int i = 0; i < payload.size(); ++i) {
    //     std::cout << "0x" << std::hex << int(payload[i]) << ", ";
    // }
    // std::cout << std::endl;
    // std::vector<uint8_t> payload_cbor = {
    //     0x83, 0x58, 0x1c, 0x9c, 0x70, 0x85, 0x38, 0xa7, 0x63, 0xff, 0x27, 0x16, 0x99, 0x87, 0xa4, 0x89, 0xe3, 0x50, 
    //     0x57, 0xef, 0x3c, 0xd3, 0x77, 0x8c, 0x05, 0xe9, 0x6f, 0x7b, 0xa9, 0x45, 0x0e, 0xa2, 0x01, 0x58, 0x1e, 0x58, 
    //     0x1c, 0x9c, 0x17, 0x22, 0xf7, 0xe4, 0x46, 0x68, 0x92, 0x56, 0xe1, 0xa3, 0x02, 0x60, 0xf3, 0x51, 0x0d, 0x55,
    //     0x8d, 0x99, 0xd0, 0xc3, 0x91, 0xf2, 0xba, 0x89, 0xcb, 0x69, 0x77, 0x02, 0x45, 0x1a, 0x41, 0x70, 0xcb, 0x17, 
    //     0x00 
    // };
    // // auto payload_json = json::from_cbor(payload_cbor);

    // // auto payload_json = json::from_cbor(payload);//, false, true, json::cbor_tag_handler_t::store);
    // std::cout << payload_json.dump(4) << std::endl;

    std::cout << addr_base58 << std::endl;

    //TEST_ASSERT_THROW( addr.toBase58() == addr_base58 )
}

void testAdvanced() {

    std::vector<uint8_t> cbor = {
        0x82, 0xD8, 0x18, 0x58, 0x49, 0x83, 0x58, 0x1C, 0x9C, 0x70, 0x85, 0x38, 0xA7, 0x63, 0xFF, 0x27,
        0x16, 0x99, 0x87, 0xA4, 0x89, 0xE3, 0x50, 0x57, 0xEF, 0x3C, 0xD3, 0x77, 0x8C, 0x05, 0xE9, 0x6F,
        0x7B, 0xA9, 0x45, 0x0E, 0xA2, 0x01, 0x58, 0x1E, 0x58, 0x1C, 0x9C, 0x17, 0x22, 0xF7, 0xE4, 0x46,
        0x68, 0x92, 0x56, 0xE1, 0xA3, 0x02, 0x60, 0xF3, 0x51, 0x0D, 0x55, 0x8D, 0x99, 0xD0, 0xC3, 0x91,
        0xF2, 0xBA, 0x89, 0xCB, 0x69, 0x77, 0x02, 0x45, 0x1A, 0x41, 0x70, 0xCB, 0x17, 0x00, 0x1A, 0x69,
        0x79, 0x12, 0x6C
    };

    // auto addr = cardano::ByronAddress();

}

int main() {
  testBasic();
  testAdvanced();
  return 0;
}