#include <array>
#include <cardano/address.hpp>
#include <cardano/encodings.hpp>
#include <cardano/ledger.hpp>
#include <cardano/transaction.hpp>
#include <set>
#include <string>
#include <test/tests.hpp>

auto testBasic() -> void
{
    // auto from_skey_cbor =
    //     "58201bd8bb327a5b3c105015ac70c055f6a7221e55c8b988c1b4117e78591ad1e5fe";
    auto from_addr_bech32 =
        "addr_"
        "test1qzqcspr8cx0djx9ds9wtn9nan6k2mpw8dxc0jf4ds666urdyc9pn6xptv3c5tcx7r"
        "rzpgpzh9tyzw7ytch8709p2da6s7k8m55";
    auto to_addr_bech32 =
        "addr_"
        "test1qqvhpysx9zcmwf937dr4ka5j7qc8fmstu8qdf0s6j78rl54x0vy5dzuykz980fhmn"
        "rxjqe2ud8qqmnee8826wvzq4z7qp6ks64";
    auto tx_id_hex =
        "768c6a03fb1cf2787efa0a7bf4f6b80165193996c280b0806f5f7d2ba9c681b5";
    auto tx_input_hex =
        "B64DEAFA7F726818607A23B354F9D3ACF945A94FE53D6C54B75715565D4DD626";
    auto tx_input_index = 0UL;
    auto tx_input_value = 100000000UL;  // lovelaces
    auto tx_amount = 10000000UL;        // lovelaces

    auto tx = cardano::babbage::Transaction();

    // Build the transaction input. The UTxO must exist in the wallet and will
    // be consumed by the transaction. The corresponding outputs will be
    // automatically created.
    auto tx_input_bytes = cardano::BASE16::decode(tx_input_hex);
    auto tx_input_id = std::array<uint8_t, 32>{};
    std::move(
        tx_input_bytes.begin(), tx_input_bytes.begin() + 32, tx_input_id.begin()
    );
    tx.body.inputs.insert({tx_input_id, tx_input_index, tx_input_value});

    // Create the to and from address objects from the bech32 strings
    auto to_addr = cardano::BaseAddress::fromBech32(to_addr_bech32);
    auto from_addr = cardano::BaseAddress::fromBech32(from_addr_bech32);

    // Add the outputs
    auto output1 = cardano::babbage::Transaction::Output();
    output1.type = cardano::babbage::Transaction::Output::Type::
        post_alonzo_transaction_output;
    output1.address = from_addr.toBytes(true);
    output1.value = 89826139UL;
    tx.body.outputs.push_back(output1);

    auto output2 = cardano::babbage::Transaction::Output();
    output2.type = cardano::babbage::Transaction::Output::Type::
        post_alonzo_transaction_output;
    output2.address = to_addr.toBytes(true);
    output2.value = tx_amount;
    tx.body.outputs.push_back(output2);

    // Add the fees
    tx.body.fee = 173861UL;

    // Add TTL
    tx.body.ttl = 7583054UL;

    // Compare the Transaction IDs (Tx body hash)
    TEST_ASSERT_THROW(
        cardano::TxSerializer::getID(tx) == cardano::BASE16::decode(tx_id_hex)
    )
}

auto testAdvanced() -> void
{
    // Build a more advanced transaction here
}

auto main() -> int
{
    testBasic();
    testAdvanced();
    return 0;
}