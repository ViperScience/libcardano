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

#include <cardano/transaction.hpp>

// Standard library headers

// Third-party library headers
#include <botan/hash.h>
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

// Public libcardano headers

// Private libcardano code
#include "utils.hpp"

using namespace cardano;

namespace  // unnammed namespace
{

}  // namespace

auto BabbageTransactionBuilder::addInput(
    std::span<const uint8_t> id,
    uint64_t index
) -> BabbageTransactionBuilder&
{
    if (id.size() < 32) throw std::invalid_argument("Not a valid input ID.");

    auto input = babbage::TransactionInput();
    std::copy_n(id.begin(), 32, input.transaction_id.begin());
    input.index = index;
    this->tx_.transaction_body.transaction_inputs.insert(std::move(input));

    return *this;
}  // BabbageTransactionBuilder::addInput

auto BabbageTransactionBuilder::addOutput(
    const BaseAddress& addr,
    uint64_t amount
) -> BabbageTransactionBuilder&
{
    auto output = babbage::PostAlonzoTransactionOutput();
    output.address = addr.toBytes(true);
    output.amount = amount;

    this->tx_.transaction_body.transaction_outputs.push_back(output);

    return *this;
}  // BabbageTransactionBuilder::addOutput

auto BabbageTransactionBuilder::addOutput(
    const EnterpriseAddress& addr,
    uint64_t amount
) -> BabbageTransactionBuilder&
{
    auto output = babbage::PostAlonzoTransactionOutput();
    output.address = addr.toBytes(true);
    output.amount = amount;

    this->tx_.transaction_body.transaction_outputs.push_back(output);

    return *this;
}  // BabbageTransactionBuilder::addOutput

auto BabbageTransactionBuilder::setTtl(size_t ttl) -> BabbageTransactionBuilder&
{
    this->tx_.transaction_body.ttl = ttl;
    return *this;
}  // BabbageTransactionBuilder::setTtl

auto BabbageTransactionBuilder::setFee(size_t fee) -> BabbageTransactionBuilder&
{
    this->tx_.transaction_body.fee = fee;
    return *this;
}  // BabbageTransactionBuilder::setTtl

auto BabbageTransactionBuilder::getID() const -> std::array<uint8_t, 32>
{
    auto txbytes = this->tx_.transaction_body.serialize();

    // Blake2b-SHA256 hash the CBOR encoded transaction body.
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(txbytes.data(), txbytes.size());
    return utils::makeByteArray<32>(blake2b->final());
}  // BabbageTransactionBuilder::getID

auto BabbageTransactionBuilder::makeWitness(const bip32_ed25519::PrivateKey& skey)
    -> std::array<uint8_t, bip32_ed25519::SIGNATURE_SIZE>
{
    return skey.sign(this->getID());
}  // BabbageTransactionBuilder::makeWitness

auto BabbageTransactionBuilder::sign(const bip32_ed25519::PrivateKey& skey)
    -> BabbageTransactionBuilder&
{
    // Create the witness.
    const auto witness = this->makeWitness(skey);

    // Put the public key in a constant size array.
    const auto key = utils::makeByteArray<32>(skey.publicKey().bytes());

    // Add the witness to the transaction witness set.
    this->tx_.transaction_witness_set.vkeywitnesses.push_back({key, witness});

    return *this;
}  // BabbageTransactionBuilder::sign

auto BabbageTransactionBuilder::serialize() const -> std::vector<uint8_t>
{
    return this->tx_.serialize();
}  // BabbageTransactionBuilder::serialize

// auto compute_fees <- TODO

// auto TxBuilder::newPaymentDraft(
//     const BaseAddress& to_addr,
//     const BaseAddress& from_addr,
//     uint64_t lovelaces,
//     std::span<const UTxO> inputs
// ) -> Transaction
// {
//     auto tx = Transaction();
//     for (auto utxo : inputs)
//         tx.body.inputs.insert({utxo.getId(), utxo.getIndex(),
//         utxo.getValue()});
//     tx.body.outputs.push_back(make_alonzo_output(from_addr.toBytes(true),
//     0)); tx.body.outputs.push_back(
//         make_alonzo_output(to_addr.toBytes(true), lovelaces)
//     );
//     return tx;
// }  // TxBuilder::newPaymentDraft

// auto TxBuilder::newPayment(
//     const BaseAddress& to_addr,
//     const BaseAddress& from_addr,
//     uint64_t lovelaces,
//     std::span<const UTxO> inputs,
//     uint64_t ttl
// ) -> Transaction
// {
//     auto tx = Transaction();
//     for (auto utxo : inputs)
//         tx.body.inputs.insert({utxo.getId(), utxo.getIndex(),
//         utxo.getValue()});
//     tx.body.outputs.push_back(make_alonzo_output(from_addr.toBytes(true),
//     0)); tx.body.outputs.push_back(
//         make_alonzo_output(to_addr.toBytes(true), lovelaces)
//     );
//     tx.body.ttl = ttl;
//     // Calculate fees and set outputs (iterative process)
//
//     return tx;
// }  // TxBuilder::newPayment
