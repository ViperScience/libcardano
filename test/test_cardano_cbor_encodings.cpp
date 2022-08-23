#include <cardano/encodings.hpp>
#include <test/tests.hpp>

auto testStatic() -> void
{
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