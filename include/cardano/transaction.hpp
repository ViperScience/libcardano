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

// Standard library headers
#include <array>
#include <cstdint>
#include <vector>

// Libcardano headers
#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/ledger.hpp>

namespace cardano
{

enum class Era
{
    Byron,
    Shelley,
    Allegra,
    Mary,
    Alonzo,
    Babbage,
    Conway
};

// class ShelleyTransactionBuilder
// {
//   private:
//     const Era era_ = Era::Shelley;
//     shelley::Transaction tx_;
// };

class BabbageTransactionBuilder
{
  private:
    const Era era_ = Era::Babbage;
    babbage::Transaction tx_;

  public:
    BabbageTransactionBuilder() : tx_{babbage::Transaction{}} {};

    /// @brief Construct a transaction builder object from a Shelley era
    /// transaction structure.
    /// @param tx The transaction structure.
    explicit BabbageTransactionBuilder(babbage::Transaction tx)
        : tx_{std::move(tx)}
    {
    }

    /// @brief Static method to create a transaction from CBOR data.
    ///
    [[nodiscard]] static auto fromCBOR(std::span<const uint8_t> cbor_bytes)
        -> BabbageTransactionBuilder;

    [[nodiscard]] auto getEra() const -> Era { return era_; }

    /// @brief Add an input to the transaction.
    /// @param id Transaction ID of the input UTxO.
    /// @param index Index of the input UTxO.
    /// @return A reference to the transaction builder.
    auto addInput(std::span<const uint8_t> id, uint64_t index)
        -> BabbageTransactionBuilder&;

    auto addOutput(const BaseAddress& addr, uint64_t amount)
        -> BabbageTransactionBuilder&;

    auto addOutput(const EnterpriseAddress& addr, uint64_t amount)
        -> BabbageTransactionBuilder&;

    /// @brief Set the transaction fee.
    /// @param fee The transaction fee in lovelaces.
    /// @return A reference to the transaction builder.
    auto setFee(size_t fee) -> BabbageTransactionBuilder&;

    /// @brief Set the transaction time to live.
    /// @param ttl The transaction time to live in slots.
    /// @return A reference to the transaction builder.
    auto setTtl(size_t ttl) -> BabbageTransactionBuilder&;

    auto addMint(
        const std::array<uint8_t, 32>& policy_id,
        std::vector<std::span<const uint8_t>> asset_names,
        std::vector<size_t> asset_counts
    ) -> BabbageTransactionBuilder&;

    /// @brief Sign the transaction and add the signature to the witness set.
    /// @param skey The signing key.
    /// @return A reference to the transaction builder.
    auto sign(const BIP32PrivateKey& skey) -> BabbageTransactionBuilder&;

    /// @brief Compute the transaction ID.
    /// @note The transaction ID is the hash (Blake2b256) of the transaction
    /// body CBOR. This ID is what is signed by the signing keys to signify
    /// transaction validity.
    [[nodiscard]] auto getID() const -> std::array<uint8_t, 32>;

    /// @brief Sign the transaction and return the signature.
    /// @param skey The signing key.
    /// @returns The signature.
    [[nodiscard]] auto makeWitness(const BIP32PrivateKey& skey)
        -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>;

    /// @brief Serialize the transaction to a CBOR byte vector.
    /// @return The serialized transaction bytes.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>;
};

using TransactionBuilder = BabbageTransactionBuilder;

// static constexpr size_t TX_SIGNATURE_SIZE = 64;
//
// /// Represent an unspent transaction output (UTxO).
// class UTxO
// {
//   public:
//     UTxO(std::array<uint8_t, 32> id, uint64_t index, uint64_t value)
//         : id_{id}, index_{index}, value_{value}
//     {
//     }
//
//     auto getId() const -> std::array<uint8_t, 32> { return id_; }
//     auto getIndex() const -> uint64_t { return index_; }
//     constexpr auto getValue() const -> uint64_t { return value_; }
//
//     // This is required for using within a std::set.
//     constexpr bool operator<(const UTxO& rhs) const
//     {
//         return this->value_ < rhs.getValue();
//     }
//
//   private:
//     std::array<uint8_t, 32> id_{};
//     uint64_t index_;
//     uint64_t value_;
// };
//
// class TxBuilder
// {
//   public:
//     /// Static method to create a simple payment transaction draft. The
//     /// transaction draft has no signatures and other parameters blank.
//     static auto newPaymentDraft(
//         const BaseAddress& to_addr,
//         const BaseAddress& from_addr,
//         uint64_t lovelaces,
//         std::span<const UTxO> inputs
//     ) -> babbage::Transaction;
//
//     /// Static method to create a simple payment transaction with fees and .
//     static auto newPayment(
//         const BaseAddress& to_addr,
//         const BaseAddress& from_addr,
//         uint64_t lovelaces,
//         std::span<const UTxO> inputs,
//         uint64_t ttl
//     ) -> babbage::Transaction;
//
//   private:
// };
//

}  // namespace cardano

#endif  // _CARDANO_TRANSACTION_HPP_