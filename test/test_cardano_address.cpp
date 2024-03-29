#include <iostream>
#include <string>

#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

#include "tests.hpp"

void testBasic() {
}

void testAdvanced() {
    std::string root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
    std::string base_addr_bech32 = "addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n";
    std::string stake_addr_bech32 = "stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat";
    std::string payment_addr_bech32 = "addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v";
    std::string password = "password";

    auto root_xsk = cardano::BIP32PrivateKey::fromBech32(root_xsk_bech32);
    auto acct_xsk = root_xsk.deriveChild(cardano::HardenIndex(1852))
                            .deriveChild(cardano::HardenIndex(1815))
                            .deriveChild(cardano::HardenIndex(0));
    auto acct_xvk = acct_xsk.toPublic();
    auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
    auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);
   
    auto addr = cardano::BaseAddress::fromKeys(cardano::NetworkID::testnet, addr_xvk, stake_xvk);
    TEST_ASSERT_THROW( addr.toBech32("addr_test") == base_addr_bech32 )
    TEST_ASSERT_THROW( cardano::BaseAddress::fromBech32(base_addr_bech32).toBech32("addr_test") == base_addr_bech32 )
 
    auto pmt_addr = cardano::EnterpriseAddress::fromKey(cardano::NetworkID::testnet, addr_xvk);
    TEST_ASSERT_THROW( pmt_addr.toBech32("addr_test") == payment_addr_bech32 )
    TEST_ASSERT_THROW( cardano::EnterpriseAddress::fromBech32(payment_addr_bech32).toBech32("addr_test") == payment_addr_bech32 )

    auto stake_addr = cardano::RewardsAddress::fromKey(cardano::NetworkID::testnet, stake_xvk);
    TEST_ASSERT_THROW( stake_addr.toBech32("stake_test") == stake_addr_bech32 )
    TEST_ASSERT_THROW( cardano::RewardsAddress::fromBech32(stake_addr_bech32).toBech32("stake_test") == stake_addr_bech32 )

    TEST_ASSERT_THROW( stake_addr.toBase16() == std::string("f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a") )
    TEST_ASSERT_THROW( stake_addr.toBase16(true) == std::string("e0f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a") )
    TEST_ASSERT_THROW( pmt_addr.toBase16() == std::string("54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9") )
    TEST_ASSERT_THROW( pmt_addr.toBase16(true) == std::string("6054947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9") )
    TEST_ASSERT_THROW( addr.toBase16() == std::string("54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a") )
    TEST_ASSERT_THROW( addr.toBase16(true) == std::string("0054947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a") )
}

int main() {
  testBasic();
  testAdvanced();
  return 0;
}