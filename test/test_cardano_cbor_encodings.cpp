#include <cardano/encodings.hpp>
#include <src/utils.hpp>
#include <test/tests.hpp>

using namespace cardano;

auto testStatic() -> void
{
    auto hex = 
        "D50FD5896BE4FBB14CEF53EB6B8D0F025B6A4D9B1F17FDEC28F1BF027508777D728AB0"
        "DEF208321AF02E406F0AF83AF6123A1A55FEFAA4D9FB4096220D40B0F0";
    auto cbor_bytes = CBOR::encode(BASE16::decode(hex));
    auto decoded_cbor = BASE16::encode(CBOR::decodeBytes(cbor_bytes));
    TEST_ASSERT_THROW( strcmpi(hex, decoded_cbor) )
}

auto testEncode() -> void
{
}
#include <iostream>

auto testSimpleDecode() -> void
{
    // Decode an array of unsigned integers: [1, 2, 3, 4].
    auto decoder = CBOR::Decoder::fromArrayData(BASE16::decode("8401020304"));
    TEST_ASSERT_THROW( decoder.getUint8()  == 1 )
    TEST_ASSERT_THROW( decoder.getUint16() == 2 )
    TEST_ASSERT_THROW( decoder.getUint32() == 3 )
    TEST_ASSERT_THROW( decoder.getUint64() == 4 )
}
#include <src/debug_utils.hpp>
using namespace cardano_debug;
auto testDecode() -> void
{
    // CBOR From an example Transaction
    auto tx_hex = 
        "83a500818258206a755909acb6803b6558fe2e8c7c9f7ef65b4465af071b741dcc7788"
        "52e52f2100018182583901a5b26e667f8257dd81e03fa883d5f81970598f84ab76e66a"
        "baa62971b95756eb2547aa744d57a5fdf94bc68f5b62c2d271ebdf6348f8144e1a1d94"
        "d393021a0003509d031a01771fb304818a03581cd69b6b16c6a135c4157365ded9b0d7"
        "72d44c7628a05b49741d3ae25c5820d6901eb064a2233d11f007ba3bc634f42d90016a"
        "b585eab5c471f91c292562df1b0000004526945a001a1443fd00d81e82011832581de1"
        "b95756eb2547aa744d57a5fdf94bc68f5b62c2d271ebdf6348f8144e84581c30188f57"
        "4458076f6746c4d0b7904247dd477db7d0be91fc919eedfe581c41ca6c5e38d392f51b"
        "c8f4f9e036a137a3c9e1e4267937d804548477581cba869b82f74e808d43af1ee2c801"
        "eb5ebdfec536b57891d625d7e35a581cfc4660b9d9ed601c168881b25d1ddb8081e122"
        "2f0901ed1bccc220b181830119115c7772656c6179302e76697065727374616b696e67"
        "2e636f6d82783968747470733a2f2f76697065727374616b696e672e636f6d2f617373"
        "6574732f66696c65732f56495045525f6d657461646174612e6a736f6e5820c74715ac"
        "7b726d24da9d2a847d3428638cd7b4ba3652e92128e5fe6c3e3b496ca100868258206a"
        "2c5aeeb651a5442e63066c911a2ab5721705c0c9e1f0a803cdddb8f557cecd58409d64"
        "2f5ab9839c2a015fbaa4919f7145846e9ec0ace3cff45ef156f151d2717557cf66f2b5"
        "497389e302046f6c16bd0ff65d8eccabf6f6fc8594e6a0d5e93002825820fa7719046b"
        "9092c6e00434bd1191a92ae8e7c4eccc6996e328b29061c8e2b5d85840d78677476a53"
        "ceffdd212bbc52e5b2e69a58422009a883e45f8ef253b48f2e13b3147b0570b749cd78"
        "e60048732fb0a4474a5531e9525c8e33304b2e7018ec0682582071280f0fa36d8faa3e"
        "d7fc1a9cd08ec430626da0b1dc39399cae7d7edcb83960584021ed9907150b56c15da1"
        "9e0a4ad5cf29f852283a216f13f175e4d0779b958dab627a8a9ac043a70fac59515a87"
        "6ff774ff35a034ef12661f1e950b51e257460182582014a0c85657b6f420579100cbaa"
        "1a02f41421f82cbf9f47a414969041470179d05840b97bbd9e5342d077fb4a4ef228fc"
        "ed9141634e8d4067534d7282f3706d2bcc6018fb07294f5ddb4f8f27062f307ea1896c"
        "e085a3d9ace6fca6d5132216a1410a825820db1329e4a9cda414ff452d0e0976e53a45"
        "06e6b64994e90bd5a9ce1c68f909695840c511a3a3a887a4ed771bce7b83190a284d75"
        "825d564cf15d47ae1b2e68fd985ba6150223611200746d61489d8c43c089f476f3d102"
        "54e3d5b8587bcad42b840a825820fb90b2ada304105355503571592362a1ce6f55dbb3"
        "ca5df7fe08f4624e2af4bc58400681fa3dd587508479b5e09ea40e7e76d86f0b659d65"
        "6f6f0dfe6762f9a70d070b7d5092c36262cdb0790355ee4a350bec43363249eb06707c"
        "b1dcb2ad975e09f6";

    auto tx_input_hex = 
        "6A755909ACB6803B6558FE2E8C7C9F7EF65B4465AF071B741DCC778852E52F21";

    auto tx_output_addr_bech32 = 
        "addr1qxjmymnx07p90hvpuql63q74lqvhqkv0sj4hden2h2nzjude2atwkf284f6y64a9l"
        "hu5h350td3v95n3a00kxj8cz38q6j544x";

    auto stake_pool_id = 
        "D69B6B16C6A135C4157365DED9B0D772D44C7628A05B49741D3AE25C";
    
    auto stake_pool_vrf = 
        "D6901EB064A2233D11F007BA3BC634F42D90016AB585EAB5C471F91C292562DF";
    
    auto stake_pool_relay_dns = "relay0.viperstaking.com";

    auto stake_pool_metadata_url = 
        "https://viperstaking.com/assets/files/VIPER_metadata.json";
    
    // Create a CBOR decoder with the transaction CBOR data. The transaction is
    // a CBOR array at the top level.
    auto tx_decoder = CBOR::Decoder::fromArrayData(BASE16::decode(tx_hex));
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 3 )

    // Open the first item in the transaction, the transaction body which is
    // contained within a map structure.
    tx_decoder.enterMap();

    // There are 5 elements in this transaction body. 
    TEST_ASSERT_THROW( tx_decoder.getMapSize() == 5 )

    // Open the transaction inputs. In this case there is only one.
    tx_decoder.enterArrayFromMap(0);
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 1 )

    // Examine the transaction input. Each input is a two element array of
    // transaction ID and output index.
    tx_decoder.enterArray();
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 2 )
    TEST_ASSERT_THROW( tx_decoder.getBytes() == BASE16::decode(tx_input_hex) )
    TEST_ASSERT_THROW( tx_decoder.getUint8() == 0 )
    tx_decoder.exitArray();

    // Exit the list of transaction inputs.
    tx_decoder.exitArray();

    // Open the transaction outputs. In this case there is only one.
    tx_decoder.enterArrayFromMap(1);
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 1 )

    // Examine the transaction output. In this case, each output is a two 
    // element array of address (bytes) and amount (lovelace).
    tx_decoder.enterArray();
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 2 )
    auto [hrp, addr_bytes] = BECH32::decode(tx_output_addr_bech32);
    TEST_ASSERT_THROW( tx_decoder.getBytes() == addr_bytes )
    TEST_ASSERT_THROW( tx_decoder.getUint32() == 496292755 )
    tx_decoder.exitArray();

    // Exit the list of transaction outputs.
    tx_decoder.exitArray();

    // Check the fees
    TEST_ASSERT_THROW( tx_decoder.getUint64FromMap(2) == 217245 )

    // Check the TTL
    TEST_ASSERT_THROW( tx_decoder.getUint64FromMap(3) == 24584115 )

    // Examine the certificate in this transaction (stake pool registration).
    tx_decoder.enterArrayFromMap(4);
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 1 )
    tx_decoder.enterArray(); // Certificate object (array)
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 10 )
    TEST_ASSERT_THROW( tx_decoder.getUint8() == 3 ) // stake pool registration
    TEST_ASSERT_THROW( tx_decoder.getBytes() == BASE16::decode(stake_pool_id) )
    TEST_ASSERT_THROW( tx_decoder.getBytes() == BASE16::decode(stake_pool_vrf) )
    TEST_ASSERT_THROW( tx_decoder.getUint64() == 297000000000 ) // pledge
    TEST_ASSERT_THROW( tx_decoder.getUint64() == 340000000 ) // min fixed fee
    auto [num, den] = tx_decoder.getRational(); // Margin
    TEST_ASSERT_THROW( ((double)num)/((double)den) == 0.02 )
    TEST_ASSERT_THROW( tx_decoder.getBytes().size() == 29 ) // reward account
    tx_decoder.enterArray(); // Array of pool owner key hashes.
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 4 )
    tx_decoder.exitArray(); // Array of pool owner key hashes
    tx_decoder.enterArray(); // Array of pool relays
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 1 )
    tx_decoder.enterArray(); // Relay object (array)
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 3 )
    TEST_ASSERT_THROW( tx_decoder.getUint64() == 1 ) // single host name
    TEST_ASSERT_THROW( tx_decoder.getUint64() == 4444 ) // Port number
    TEST_ASSERT_THROW( tx_decoder.getString() == stake_pool_relay_dns) // DNS
    tx_decoder.exitArray(); // Relay object (array)
    tx_decoder.exitArray(); // Array of pool relays
    tx_decoder.enterArray(); // Pool metadata
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 2 )
    TEST_ASSERT_THROW( tx_decoder.getString() == stake_pool_metadata_url)
    TEST_ASSERT_THROW( tx_decoder.getBytes().size() == 32 )
    tx_decoder.exitArray(); // Pool metadata
    tx_decoder.exitArray(); // Certificate object (array)
    tx_decoder.exitArray(); // Array of certificates

    // Exit the transaction body.
    tx_decoder.exitMap();

    // Open the second item in the transaction, the transaction witness set.
    tx_decoder.enterMap();

    // There is only one type of witness set for this transaction: VKeys. 
    TEST_ASSERT_THROW( tx_decoder.getMapSize() == 1 )

    // And there are six signatories.
    tx_decoder.enterArrayFromMap(0);
    TEST_ASSERT_THROW( tx_decoder.getArraySize() == 6 )
    tx_decoder.exitArray();

    // Exit the transaction witness set.
    tx_decoder.exitMap();

    // Test that the last item in the array is a null character.
    TEST_ASSERT_THROW( tx_decoder.getNULL() )
}

auto main() -> int
{
    testStatic();
    testEncode();
    testSimpleDecode();
    testDecode();
    return 0;
}