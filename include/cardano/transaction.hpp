// Copyright (c) 2021 Viper Science LLC
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

#ifndef _CARDANO_TRANSACTION_HPP_
#define _CARDANO_TRANSACTION_HPP_

#include <array>
#include <cardano/address.hpp>
#include <cardano/ledger.hpp>
#include <cstdint>
#include <vector>

namespace cardano
{

static constexpr size_t TX_SIGNATURE_SIZE = 64;

/// Represent an unspent transaction output (UTxO).
class UTxO
{
  public:
    UTxO(std::array<uint8_t, 32> id, uint64_t index, uint64_t value)
        : id_{id}, index_{index}, value_{value}
    {
    }

    auto getId() const -> std::array<uint8_t, 32> { return id_; }
    auto getIndex() const -> uint64_t { return index_; }
    auto getValue() const -> uint64_t { return value_; }

    // This is required for using within a std::set.
    constexpr bool operator<(const UTxO& rhs) const
    {
        return this->value_ < rhs.getValue();
    }

  private:
    std::array<uint8_t, 32> id_{};
    uint64_t index_;
    uint64_t value_;
};

class TxBuilder
{
  public:
    /// Static method to create a simple payment transaction draft. The
    /// transaction draft has no signatures and other parameters blank.
    static auto newPaymentDraft(
        const BaseAddress& to_addr,
        const BaseAddress& from_addr,
        uint64_t lovelaces,
        std::span<const UTxO> inputs
    ) -> babbage::Transaction;

    /// Static method to create a simple payment transaction with fees and .
    static auto newPayment(
        const BaseAddress& to_addr,
        const BaseAddress& from_addr,
        uint64_t lovelaces,
        std::span<const UTxO> inputs,
        uint64_t ttl
    ) -> babbage::Transaction;

  private:
};

class TxSerializer
{
  public:
    /// Static method to create a transaction from CBOR data.
    [[nodiscard]] static auto fromCBOR() -> babbage::Transaction;

    /// @brief Compute the transaction ID.
    // The transaction ID is the hash (Blake2b256) of the transaction body CBOR.
    // This ID is what is signed by the signing keys to signify transaction
    // validity.
    [[nodiscard]] static auto getID(const babbage::Transaction& tx)
        -> std::vector<uint8_t>;

    /// Static method to create a transaction from CBOR data.
    [[nodiscard]] static auto toCBOR(const babbage::Transaction& tx)
        -> std::vector<uint8_t>;

  private:
};

class TxSigner
{
  public:
    ///
    static auto makeWitness(
        const babbage::Transaction& tx, const BIP32PrivateKey& skey
    ) -> std::vector<uint8_t>;

    ///
    static auto sign(babbage::Transaction& tx, const BIP32PrivateKey& skey)
        -> void;

  private:
    ///
};

}  // namespace cardano

#endif  // _CARDANO_TRANSACTION_HPP_