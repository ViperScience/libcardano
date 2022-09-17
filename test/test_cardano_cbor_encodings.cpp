#include <cardano/encodings.hpp>
#include <src/utils.hpp>
#include <test/tests.hpp>

using namespace cardano;

auto testStatic() -> void
{
    auto hex = "D50FD5896BE4FBB14CEF53EB6B8D0F025B6A4D9B1F17FDEC28F1BF027508777D728AB0DEF208321AF02E406F0AF83AF6123A1A55FEFAA4D9FB4096220D40B0F0";
    auto cbor_bytes = CBOR::encode(BASE16::decode(hex));
    auto decoded_cbor = BASE16::encode(CBOR::decodeBytes(cbor_bytes));
    TEST_ASSERT_THROW( strcmpi(hex, decoded_cbor) )
}

auto testEncode() -> void
{
}

auto testDecode() -> void
{
    // Decode an array of unsigned integers: [1, 2, 3, 4].
    auto decoder = cardano::CBOR::Decoder::fromArrayData(
        cardano::BASE16::decode("8401020304")
    );
    TEST_ASSERT_THROW( decoder.getUint8()  == 1 )
    TEST_ASSERT_THROW( decoder.getUint16() == 2 )
    TEST_ASSERT_THROW( decoder.getUint32() == 3 )
    TEST_ASSERT_THROW( decoder.getUint64() == 4 )
}

auto main() -> int
{
    testStatic();
    testEncode();
    testDecode();
    return 0;
}