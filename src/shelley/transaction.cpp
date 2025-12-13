// Copyright (c) 2025 Viper Science LLC
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

#include <algorithm>
#include <cardano/transaction.hpp>

// Standard library headers
#include <cstdint>
#include <utility>

// Third-party library headers
#include <botan/hash.h>
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

// Public libcardano headers
#include <cardano/encodings.hpp>
#include <cardano/util.hpp>

namespace cardano::shelley
{

auto UTxO::fromJSON(const json& j) -> UTxO
{
    const auto id = BASE16::decode(j["transaction"]["id"].get<std::string>());
    const auto index = j["index"].get<uint64_t>();
    const auto value = j["value"]["ada"]["lovelace"].get<uint64_t>();
    return UTxO(cardano::util::makeByteArray<32>(id), index, value);
}  // UTxO::fromJSON

auto TransactionBuilder::fromCBOR(std::span<const uint8_t> cbor_bytes
) -> TransactionBuilder
{
    auto tx = shelley::Transaction{};
    tx.deserialize(cbor_bytes);
    return TransactionBuilder(tx);
}  // TransactionBuilder::fromCBOR

auto TransactionBuilder::addInput(const UTxO& utxo) -> TransactionBuilder&
{
    if (utxo.id().size() < 32)
        throw std::invalid_argument("Not a valid input ID.");
    this->clearWitnessSet();

    auto input = shelley::TransactionInput();
    std::copy_n(utxo.id().begin(), 32, input.transaction_id.begin());
    input.index = utxo.index();
    this->tx_.transaction_body.transaction_inputs.insert(std::move(input));

    this->input_total_ += utxo.value();

    return *this;
}  // TransactionBuilder::addInput

auto TransactionBuilder::addOutput(const BaseAddress& addr, uint64_t amount)
    -> TransactionBuilder&
{
    this->clearWitnessSet();
    auto output = shelley::TransactionOutput{};
    output.address = addr.toBytes();
    output.amount = amount;
    this->tx_.transaction_body.transaction_outputs.push_back(output);
    return *this;
}  // TransactionBuilder::addOutput

auto TransactionBuilder::addOutput(
    const EnterpriseAddress& addr,
    uint64_t amount
) -> TransactionBuilder&
{
    this->clearWitnessSet();
    auto output = shelley::TransactionOutput{};
    output.address = addr.toBytes();
    output.amount = amount;
    this->tx_.transaction_body.transaction_outputs.push_back(output);
    return *this;
}  // TransactionBuilder::addOutput

auto TransactionBuilder::addWithdrawal(
    const RewardsAddress& addr,
    uint64_t amount
) -> TransactionBuilder&
{
    this->clearWitnessSet();
    this->tx_.transaction_body.withdrawals[addr.toBytes()] = amount;
    this->input_total_ += amount;
    return *this;
}  // TransactionBuilder::addWithdrawal

auto TransactionBuilder::addPoolRegistrationCertificate(
    PoolRegistration cert,
    uint64_t deposit
) -> TransactionBuilder&
{
    this->tx_.transaction_body.certificates.emplace_back(std::move(cert));
    this->deposit_total_ += deposit;
    return *this;
}  // TransactionBuilder::addPoolRegistrationCertificate

auto TransactionBuilder::addPoolRetirementCertificate(PoolRetirement cert
) -> TransactionBuilder&
{
    this->tx_.transaction_body.certificates.emplace_back(std::move(cert));
    return *this;
}  // TransactionBuilder::addPoolRetirementCertificate

auto TransactionBuilder::addStakeRegistrationCertificate(
    const RewardsAddress& addr,
    uint64_t deposit
) -> TransactionBuilder&
{
    const auto key_hash = addr.toBytesRaw();

    auto cred = StakeCredential{};
    cred.type = StakeCredential::Type::addr_keyhash;
    std::copy_n(key_hash.begin(), 28, cred.cred.begin());

    auto cert = StakeRegistration{};
    cert.stake_credential = cred;

    this->tx_.transaction_body.certificates.emplace_back(std::move(cert));
    this->deposit_total_ += deposit;
    return *this;
}  // TransactionBuilder::addStakeRegistrationCertificate

auto TransactionBuilder::addStakeDeregistrationCertificate(
    const RewardsAddress& addr
) -> TransactionBuilder&
{
    const auto key_hash = addr.toBytesRaw();

    auto cred = StakeCredential{};
    cred.type = StakeCredential::Type::addr_keyhash;
    std::copy_n(key_hash.begin(), KEY_HASH_LENGTH, cred.cred.begin());

    auto cert = StakeDeregistration{};
    cert.stake_credential = cred;

    this->tx_.transaction_body.certificates.emplace_back(std::move(cert));
    return *this;
}  // TransactionBuilder::addStakeDeregistrationCertificate

auto TransactionBuilder::addStakeDelegationCertificate(
    const RewardsAddress& addr,
    std::span<const uint8_t, stake_pool::STAKE_POOL_ID_SIZE> pool_id
) -> TransactionBuilder&
{
    const auto key_hash = addr.toBytesRaw();

    auto cred = StakeCredential{};
    cred.type = StakeCredential::Type::addr_keyhash;
    std::copy_n(key_hash.begin(), KEY_HASH_LENGTH, cred.cred.begin());

    auto cert = StakeDelegation{};
    cert.stake_credential = cred;
    std::copy_n(
        pool_id.begin(),
        stake_pool::STAKE_POOL_ID_SIZE,
        cert.pool_keyhash.begin()
    );

    this->tx_.transaction_body.certificates.emplace_back(std::move(cert));
    return *this;
}  // TransactionBuilder::addStakeDelegationCertificate

auto TransactionBuilder::setFee(size_t fee) -> TransactionBuilder&
{
    this->clearWitnessSet();
    this->tx_.transaction_body.fee = fee;
    return *this;
}  //  TransactionBuilder::setFee

auto TransactionBuilder::updateFee(uint32_t numWitnesses) -> TransactionBuilder&
{
    // Set fee estimate to 0-byte TX
    this->setFee(static_cast<uint64_t>(this->min_fee_b_));

    // Calculate the transaction fee
    auto calc_fee = this->calculateFee(numWitnesses);

    // Iteratively update the fee and fee calculation until steady state
    // reached.
    while (calc_fee != this->tx_.transaction_body.fee)
    {
        this->setFee(calc_fee);
        calc_fee = this->calculateFee(numWitnesses);
    }

    return *this;
}  // TransactionBuilder::updateFee

auto TransactionBuilder::setTtl(size_t ttl) -> TransactionBuilder&
{
    this->clearWitnessSet();
    this->tx_.transaction_body.ttl = ttl;
    return *this;
}  // TransactionBuilder::setTtl

auto TransactionBuilder::totalOutgoing() -> int64_t
{
    auto total_outputs = this->deposit_total_ +
                         static_cast<int64_t>(this->tx_.transaction_body.fee);
    for (const auto& o : this->tx_.transaction_body.transaction_outputs)
    {
        total_outputs += static_cast<int64_t>(o.amount);
    }
    return total_outputs;
}  // TransactionBuilder::sumOutputs

auto TransactionBuilder::balance(uint32_t numWitnesses, bool force) -> TransactionBuilder&
{
    auto max_iter = 100;
    for (auto i = 0;; ++i)
    {
        if (i == max_iter)
        {
            throw std::runtime_error("Unable to balance transaction...");
        }

        this->updateFee(numWitnesses);
        int64_t change = this->input_total_ - this->totalOutgoing();
        if (change == 0)
        {
            // We are done, the transaction is balanced.
            break;
        }
        else if (change < 0) // negative change value
        {
            if (this->tx_.transaction_body.transaction_outputs.size() == 0)
            {
                // There is simply not enough inputs to cover the outputs.
                throw std::runtime_error("Insufficient funds");
            }
            else
            {
                // In this case, we've already added a change output and
                // probably just need to slighly decrease the change output
                // amount to account for a small increase in fees.

                // Access the change output. If there are multiple, use the
                // last one.
                auto& change_output =
                    this->tx_.transaction_body.transaction_outputs.back();
                
                auto prev_amt = static_cast<int64_t>(change_output.amount);
                auto new_amt = prev_amt + change;  // add neg value to subtract

                if (new_amt < this->min_utxo_)
                {
                    // The change output is not viable. We need to either error
                    // or waste the extra ADA in fees. Remove the change
                    // output.
                    this->tx_.transaction_body.transaction_outputs.pop_back();
                }
                else
                {
                    change_output.amount = static_cast<Coin>(new_amt);
                }
            }
        }
        else  // positive change value
        {
            if ((i == 0) && (change > this->min_utxo_))
            {
                // Add the change output
                auto tout = shelley::TransactionOutput{};
                tout.address = this->change_addr_;
                tout.amount = static_cast<Coin>(change);
                this->tx_.transaction_body.transaction_outputs.push_back(tout);
                // The TX is not balanced yet because the fees neeed to be
                // re-computed to account for the bytes added by the change
                // output.
            }
            else
            {
                // We cannot balance the transaction unless we force it to waste
                // the extra lovelace in fees.
                if (force)
                {
                    this->tx_.transaction_body.fee += static_cast<Coin>(change);
                    if (this->tx_.transaction_body.fee <
                        this->calculateFee(numWitnesses))
                    {
                        // This is very unlikely, I suppose the only scenario is
                        // if the change was < 44 lovelaces but by increasing
                        // the fee we added another byte to the transaction
                        // size. I'm not sure if that is even possible...
                        throw std::runtime_error("Insufficient funds");
                    }
                    break;  // We are done, the transaction is balanced.
                }
            }
        }
    }
    return *this;
}  // TransactionBuilder::balance

auto TransactionBuilder::sign(const ed25519::PrivateKey& skey
) -> TransactionBuilder&
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
}  // TransactionBuilder::sign

auto TransactionBuilder::sign(const bip32_ed25519::PrivateKey& skey
) -> TransactionBuilder&
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
}  // TransactionBuilder::sign

auto TransactionBuilder::clearWitnessSet() -> void
{
    if (!this->tx_.transaction_witness_set.vkeywitnesses.empty())
    {
        this->tx_.transaction_witness_set.vkeywitnesses.clear();
    }
}  // TransactionBuilder::clearWitnessSet

auto TransactionBuilder::getID() const -> std::array<uint8_t, 32>
{
    auto txbytes = this->tx_.transaction_body.serialize();

    // Blake2b-SHA256 hash the CBOR encoded transaction body.
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(txbytes.data(), txbytes.size());
    return util::makeByteArray<32>(blake2b->final());
}  // TransactionBuilder::getID

auto TransactionBuilder::makeWitness(const ed25519::PrivateKey& skey
) -> std::array<uint8_t, ed25519::SIGNATURE_SIZE>
{
    return skey.sign(this->getID());
}  // TransactionBuilder::makeWitness

auto TransactionBuilder::makeWitness(const bip32_ed25519::PrivateKey& skey
) -> std::array<uint8_t, bip32_ed25519::SIGNATURE_SIZE>
{
    return skey.sign(this->getID());
}  // TransactionBuilder::makeWitness

auto TransactionBuilder::serialize() const -> std::vector<uint8_t>
{
    return this->tx_.serialize();
}  // TransactionBuilder::serialize

auto TransactionBuilder::calculateFee(uint32_t numWitnesses) const -> uint64_t
{
    const auto a = static_cast<uint64_t>(this->min_fee_a_);
    const auto b = static_cast<uint64_t>(this->min_fee_b_);

    // Create a temporary copy - don't modify original
    auto temp_tx = this->tx_;
    if (!temp_tx.transaction_witness_set.vkeywitnesses.empty())
    {
        temp_tx.transaction_witness_set.vkeywitnesses.clear();
    }

    // Add dummy vkey witnesses
    for (uint32_t i = 0; i < numWitnesses; ++i)
    {
        const auto dummy_key = util::makeRandomByteArray<32>();
        const auto dummy_witness = util::makeRandomByteArray<64>();
        temp_tx.transaction_witness_set.vkeywitnesses.push_back(
            {dummy_key, dummy_witness}
        );
    }

    auto calculated_fee = a * temp_tx.serialize().size() + b;
    while (calculated_fee != temp_tx.transaction_body.fee)
    {
        temp_tx.transaction_body.fee = calculated_fee;
        calculated_fee = a * temp_tx.serialize().size() + b;
    }

    return calculated_fee;
}  // TransactionBuilder::calculateFee

}  // namespace cardano::shelley
