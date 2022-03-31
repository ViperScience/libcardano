#include <iostream>
#include <string>

#include <test/tests.hpp>
#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

void testBasic() {
    std::string addr_base58 = "DdzFFzCqrhsrcTVhLygT24QwTnNqQqQ8mZrq5jykUzMveU26sxaH529kMpo7VhPrt5pwW3dXeB2k3EEvKcNBRmzCfcQ7dTkyGzTs658C";
    auto addr = cardano::ByronAddress();
    TEST_ASSERT_THROW( addr.toBase58() == addr_base58 )
}

void testAdvanced() {
}

int main() {
  testBasic();
  testAdvanced();
  return 0;
}