// Copyright (c) 2022 Viper Science LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Standard library headers

// Third-party library headers
#include <botan/hash.h>

// Public libcardano headers
#include <cardano/encodings.hpp>
#include <cardano/transaction.hpp>

// Private libcardano code
#include "utils.hpp"

using namespace cardano;
using namespace cardano::babbage;

auto make_alonzo_output(std::vector<uint8_t> addr_key_hash, uint64_t value)
    -> Transaction::Output
{
    auto output = Transaction::Output();
    output.type = Transaction::Output::Type::post_alonzo_transaction_output;
    output.address = addr_key_hash;
    output.value = value;
    return output;
}

// auto compute_fees <- TODO

auto TxBuilder::newPaymentDraft(
    const BaseAddress& to_addr,
    const BaseAddress& from_addr,
    uint64_t lovelaces,
    std::span<const UTxO> inputs
) -> Transaction
{
    auto tx = Transaction();
    for (auto utxo : inputs)
        tx.body.inputs.insert({utxo.getId(), utxo.getIndex(), utxo.getValue()});
    tx.body.outputs.push_back(make_alonzo_output(from_addr.toBytes(true), 0));
    tx.body.outputs.push_back(
        make_alonzo_output(to_addr.toBytes(true), lovelaces)
    );
    return tx;
}  // TxBuilder::newPaymentDraft

auto TxBuilder::newPayment(
    const BaseAddress& to_addr,
    const BaseAddress& from_addr,
    uint64_t lovelaces,
    std::span<const UTxO> inputs,
    uint64_t ttl
) -> Transaction
{
    auto tx = Transaction();
    for (auto utxo : inputs)
        tx.body.inputs.insert({utxo.getId(), utxo.getIndex(), utxo.getValue()});
    tx.body.outputs.push_back(make_alonzo_output(from_addr.toBytes(true), 0));
    tx.body.outputs.push_back(
        make_alonzo_output(to_addr.toBytes(true), lovelaces)
    );
    tx.body.ttl = ttl;
    // Calculate fees and set outputs (iterative process)

    return tx;
}  // TxBuilder::newPayment

auto TxSerializer::toCBOR(const Transaction& tx) -> std::vector<uint8_t>
{
    auto txcbor = CBOR::Encoder::newArray(512);

    // TX body
    txcbor.startMap();
    txcbor.startArrayInMap(0);  // Input Array (UTxOs to be consumed)
    for (auto input : tx.body.inputs)
    {
        txcbor.startArray();
        txcbor.add(input.transaction_id);
        txcbor.add(input.index);
        txcbor.endArray();
    }
    txcbor.endArray();
    txcbor.startArrayInMap(1);  // Output Array
    for (auto output : tx.body.outputs)
    {
        txcbor.startMap();
        txcbor.addToMap(0, output.address);
        txcbor.addToMap(1, output.value);
        txcbor.endMap();
    }
    txcbor.endArray();
    txcbor.addToMap(2, tx.body.fee);  // Tx fees
    txcbor.addToMap(3, tx.body.ttl);  // TTL
    //   , ? 4 : [* certificate]
    //   , ? 5 : withdrawals
    //   , ? 6 : update
    //   , ? 7 : auxiliary_data_hash
    //   , ? 8 : uint                    ; validity interval start
    //   , ? 9 : mint
    //   , ? 11 : script_data_hash
    //   , ? 13 : set<transaction_input> ; collateral inputs
    //   , ? 14 : required_signers
    //   , ? 15 : network_id
    //   , ? 16 : transaction_output     ; collateral return; New
    //   , ? 17 : coin                   ; total collateral; New
    //   , ? 18 : set<transaction_input> ; reference inputs; New
    txcbor.endMap();

    // Witnesses
    txcbor.startMap();
    if (tx.witness_set.vkeywitness_vec.size() > 0)
    {
        txcbor.startArrayInMap(0);  // ? 0: [* vkeywitness ]
        for (auto vkeywit : tx.witness_set.vkeywitness_vec)
        {
            auto [vk, sig] = vkeywit;
            txcbor.startArray();
            txcbor.add(vk);
            txcbor.add(sig);
            txcbor.endArray();
        }
        txcbor.endArray();
    }
    txcbor.endMap();

    // Bool
    txcbor.addBool(true);

    // Null
    txcbor.addNULL();

    txcbor.endArray();
    return txcbor.serialize();
}

auto TxSerializer::getID(const Transaction& tx) -> std::vector<uint8_t>
{
    // Build the transaction body CBOR
    auto txcbor = CBOR::Encoder::newMap(256);
    txcbor.startArrayInMap(0);  // Input Array (UTxOs to be consumed)
    for (auto input : tx.body.inputs)
    {
        txcbor.startArray();
        txcbor.add(input.transaction_id);
        txcbor.add(input.index);
        txcbor.endArray();
    }
    txcbor.endArray();
    txcbor.startArrayInMap(1);  // Output Array
    for (auto output : tx.body.outputs)
    {
        txcbor.startMap();
        txcbor.addToMap(0, output.address);
        txcbor.addToMap(1, output.value);
        txcbor.endMap();
    }
    txcbor.endArray();
    txcbor.addToMap(2, tx.body.fee);  // Tx fees
    txcbor.addToMap(3, tx.body.ttl);  // TTL
    txcbor.endMap();
    auto txbytes = txcbor.serialize();

    // Blake2b-SHA256 hash the CBOR encoded transaction body.
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(txbytes.data(), txbytes.size());
    const auto hashed = blake2b->final();

    return std::vector<uint8_t>(hashed.begin(), hashed.end());
}

auto TxSigner::makeWitness(const Transaction& tx, const BIP32PrivateKey& skey)
    -> std::vector<uint8_t>
{
    // The transaction ID is the message to be signed.
    const auto txid = TxSerializer::getID(tx);
    auto signature = skey.sign(txid);

    return std::vector<uint8_t>(signature.begin(), signature.end());
}  // TxSigner::makeWitness

auto TxSigner::sign(Transaction& tx, const BIP32PrivateKey& skey) -> void
{
    // Create the witness and put it in a constant size array.
    const auto witness_bytes = TxSigner::makeWitness(tx, skey);
    auto witness = std::array<uint8_t, TX_SIGNATURE_SIZE>();
    std::copy_n(witness_bytes.begin(), TX_SIGNATURE_SIZE, witness.begin());

    // Put the key in a constant size array.
    const auto pkey_bytes = skey.toPublic().toBytes(false);
    auto key = std::array<uint8_t, 32>();
    std::copy_n(pkey_bytes.begin(), 32, key.begin());

    // Add the witness to the transaction object.
    tx.witness_set.vkeywitness_vec.push_back({key, witness});
}  // TxSigner::sign
