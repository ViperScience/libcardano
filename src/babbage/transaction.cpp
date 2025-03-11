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
#include <utility>

// Third-party library headers
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/system_rng.h>
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

// Public libcardano headers
#include <cardano/util.hpp>

using namespace cardano;

namespace  // unnammed namespace
{

auto MakeDummyWitness()
    -> std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 64>>
{
    return std::make_pair(
        util::makeRandomByteArray<32>(), util::makeRandomByteArray<64>()
    );
}  // MakeDummyWitness

}  // namespace

auto babbage::TransactionBuilder::addInput(
    std::span<const uint8_t> id,
    uint64_t index
) -> babbage::TransactionBuilder&
{
    if (id.size() < 32) throw std::invalid_argument("Not a valid input ID.");
    this->clearWitnessSet();

    auto input = babbage::TransactionInput();
    std::copy_n(id.begin(), 32, input.transaction_id.begin());
    input.index = index;
    this->tx_.transaction_body.transaction_inputs.insert(std::move(input));

    return *this;
}  // babbage::TransactionBuilder::addInput

auto babbage::TransactionBuilder::addOutput(
    const BaseAddress& addr,
    uint64_t amount,
    bool prebabbage
) -> babbage::TransactionBuilder&
{
    this->clearWitnessSet();
    if (prebabbage)
    {
        auto output = babbage::PreBabbageTransactionOutput{};
        output.address = addr.toBytes();
        output.amount = amount;
        this->tx_.transaction_body.transaction_outputs.push_back(output);
    }
    else
    {
        auto output = babbage::PostAlonzoTransactionOutput{};
        output.address = addr.toBytes();
        output.amount = amount;
        this->tx_.transaction_body.transaction_outputs.push_back(output);
    }
    return *this;
}  // babbage::TransactionBuilder::addOutput

auto babbage::TransactionBuilder::addOutput(
    const EnterpriseAddress& addr,
    uint64_t amount,
    bool prebabbage
) -> babbage::TransactionBuilder&
{
    this->clearWitnessSet();
    if (prebabbage)
    {
        auto output = babbage::PreBabbageTransactionOutput{};
        output.address = addr.toBytes();
        output.amount = amount;
        this->tx_.transaction_body.transaction_outputs.push_back(output);
    }
    else
    {
        auto output = babbage::PostAlonzoTransactionOutput{};
        output.address = addr.toBytes();
        output.amount = amount;
        this->tx_.transaction_body.transaction_outputs.push_back(output);
    }
    return *this;
}  // babbage::TransactionBuilder::addOutput

auto babbage::TransactionBuilder::addWithdrawal(
    const RewardsAddress& addr,
    uint64_t amount
) -> babbage::TransactionBuilder&
{
    this->clearWitnessSet();
    this->tx_.transaction_body.withdrawals[addr.toBytes()] = amount;
    return *this;
}  // babbage::TransactionBuilder::addWithdrawal

auto babbage::TransactionBuilder::setTtl(size_t ttl
) -> babbage::TransactionBuilder&
{
    this->clearWitnessSet();
    this->tx_.transaction_body.ttl = ttl;
    return *this;
}  // babbage::TransactionBuilder::setTtl

auto babbage::TransactionBuilder::setFee(size_t fee
) -> babbage::TransactionBuilder&
{
    this->clearWitnessSet();
    this->tx_.transaction_body.fee = fee;
    return *this;
}  // babbage::TransactionBuilder::setTtl

auto babbage::TransactionBuilder::calculateFee(uint32_t numWitnesses
) -> uint64_t
{
    const auto a = this->min_fee_a_;
    const auto b = this->min_fee_b_;

    // Add dummy vkey witnesses
    this->clearWitnessSet();
    for (uint32_t i = 0; i < numWitnesses; ++i)
    {
        auto [dummy_key, dummy_witness] = MakeDummyWitness();
        this->tx_.transaction_witness_set.vkeywitnesses.push_back(
            {dummy_key, dummy_witness}
        );
    }

    auto calculated_fee = a * this->serialize().size() + b;
    while (calculated_fee != this->tx_.transaction_body.fee)
    {
        this->tx_.transaction_body.fee = calculated_fee;
        calculated_fee = a * this->serialize().size() + b;
    }
    this->clearWitnessSet();

    return calculated_fee;
}  // babbage::TransactionBuilder::calculateFee

auto babbage::TransactionBuilder::balance(uint32_t numWitnesses
) -> babbage::TransactionBuilder&
{
    auto total_input = 0;    // includes withdrawals
    auto total_outputs = 0;  // includes deposites
    // calculate fees
    // is inputs > fees + outputs?
    //   if inputs + min_utxo > fees + outputs
    ///     use change
    //    else
    //      add extra to tx fee
    // if we used the change address, start over calculating the fees
    return *this;
}

auto babbage::TransactionBuilder::getID() const -> std::array<uint8_t, 32>
{
    auto txbytes = this->tx_.transaction_body.serialize();

    // Blake2b-SHA256 hash the CBOR encoded transaction body.
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(txbytes.data(), txbytes.size());
    return util::makeByteArray<32>(blake2b->final());
}  // babbage::TransactionBuilder::getID

auto babbage::TransactionBuilder::makeWitness(const ed25519::PrivateKey& skey
) -> std::array<uint8_t, ed25519::SIGNATURE_SIZE>
{
    return skey.sign(this->getID());
}  // babbage::TransactionBuilder::makeWitness

auto babbage::TransactionBuilder::makeWitness(
    const bip32_ed25519::PrivateKey& skey
) -> std::array<uint8_t, bip32_ed25519::SIGNATURE_SIZE>
{
    return skey.sign(this->getID());
}  // babbage::TransactionBuilder::makeWitness

auto babbage::TransactionBuilder::sign(const ed25519::PrivateKey& skey
) -> babbage::TransactionBuilder&
{
    // Create the witness.
    const auto witness = this->makeWitness(skey);

    // Put the public key in a constant size array.
    const auto key = util::makeByteArray<32>(skey.publicKey().bytes());

    // Before updating the transaction witness set, remove any duplicate
    // signatures.
    for (auto it = this->tx_.transaction_witness_set.vkeywitnesses.begin();
         it != this->tx_.transaction_witness_set.vkeywitnesses.end();)
    {
        if (std::get<0>(*it) == key)
        {
            it = this->tx_.transaction_witness_set.vkeywitnesses.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Add the witness to the transaction witness set.
    this->tx_.transaction_witness_set.vkeywitnesses.push_back({key, witness});

    return *this;
}  // babbage::TransactionBuilder::sign

auto babbage::TransactionBuilder::sign(const bip32_ed25519::PrivateKey& skey
) -> babbage::TransactionBuilder&
{
    // Create the witness.
    const auto witness = this->makeWitness(skey);

    // Put the public key in a constant size array.
    const auto key = util::makeByteArray<32>(skey.publicKey().bytes());

    // Before updating the transaction witness set, remove any duplicate
    // signatures.
    for (auto it = this->tx_.transaction_witness_set.vkeywitnesses.begin();
         it != this->tx_.transaction_witness_set.vkeywitnesses.end();)
    {
        if (std::get<0>(*it) == key)
        {
            it = this->tx_.transaction_witness_set.vkeywitnesses.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Add the witness to the transaction witness set.
    this->tx_.transaction_witness_set.vkeywitnesses.push_back({key, witness});

    return *this;
}  // babbage::TransactionBuilder::sign

auto babbage::TransactionBuilder::clearWitnessSet() -> void
{
    if (!this->tx_.transaction_witness_set.vkeywitnesses.empty())
    {
        this->tx_.transaction_witness_set.vkeywitnesses.clear();
    }
}

auto babbage::TransactionBuilder::serialize() const -> std::vector<uint8_t>
{
    return this->tx_.serialize();
}  // babbage::TransactionBuilder::serialize

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
