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

// Third-Party Library Headers
#include <nlohmann/json.hpp>

// Libcardano headers
#include <cardano/address.hpp>
#include <cardano/bip32_ed25519.hpp>
#include <cardano/ed25519.hpp>
#include <cardano/genesis.hpp>
#include <cardano/ledger.hpp>
#include <cardano/stake_pool.hpp>

using json = nlohmann::json;

namespace cardano
{

/// @brief Enum to represent the various Cardano ledger eras.
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

/// @brief Interface for all transaction builders to implement.
class ITransactionBuilder
{
};

namespace shelley
{

/// @brief Represent a Shelley era unspent transaction output (UTxO).
class UTxO
{
  private:
    std::array<uint8_t, 32> id_{};
    uint64_t index_;
    uint64_t value_;

  public:
    /// @brief Create a new Shelley-Era UTxO
    /// @param id The transaction ID as a 32-byte array.
    /// @param index The transaction output index.
    /// @param value The UTxO value in lovelace.
    UTxO(std::array<uint8_t, 32> id, uint64_t index, uint64_t value)
        : id_{id}, index_{index}, value_{value}
    {
    }

    /// @brief Get a constant reference to the transaction ID.
    auto id() const -> const std::array<uint8_t, 32>& { return id_; }

    /// @brief Get the transaction output index.
    auto index() const -> uint64_t { return index_; }

    /// @brief Get the UTxO value in lovelace.
    auto value() const -> uint64_t { return value_; }

    /// @brief Provide de-serialization from JSON, i.e., Ogmios.
    /// @return A populated UTxO object.
    static auto fromJSON(const json& j) -> UTxO;

    // Comparison operators are required to provide lexigraphical sorting within
    // a std::set.

    auto operator<=>(const UTxO& other) const
    {
        if (auto cmp = this->id_ <=> other.id_; cmp != 0) return cmp;
        return this->index_ <=> other.index_;
    }

    bool operator==(const UTxO& other) const
    {
        return this->id_ == other.id_ && this->index_ == other.index_;
    }

};  // UTxO

/// @brief Build Shelley era Cardano transactions.
class TransactionBuilder : public ITransactionBuilder
{
  private:
    // Set the era to that matching the version of the class.
    const Era era_ = Era::Shelley;

    // The transaction object that will be serialized to CBOR.
    shelley::Transaction tx_{};

    // Optionally set the address to use for change when auto-balancing the
    // transaction.
    std::vector<uint8_t> change_addr_ = {};

    // The minimum transaction fee coefficients. Default to those active within
    // the era but they are setable if needed.
    int64_t min_fee_a_ = 44;
    int64_t min_fee_b_ = 155381;
    int64_t min_utxo_ = 1000000;
    int64_t pool_deposit_ = 500000000;
    int64_t key_deposit_ = 2000000;

    // Keep track of the total inputs for transaction balancing.
    int64_t input_total_ = 0;  // must init to zero

    // Keep track of the total deposits for transaction balancing.
    int64_t deposit_total_ = 0;  // must init to zero

    /// Sum all the outgoing lovelaces
    [[nodiscard]] auto totalOutgoing() -> int64_t;

  public:
    /// @brief Construct an empty transaction builder object.
    TransactionBuilder() : tx_{shelley::Transaction{}} {};

    /// @brief Construct a transaction builder object from a Shelley era
    /// transaction structure.
    /// @param tx The transaction structure.
    explicit TransactionBuilder(shelley::Transaction tx) : tx_{std::move(tx)} {}

    /// @brief Create an empty transaction builder with specific genesis
    /// parameters.
    /// @param params Shelley era genesis parameters.
    /// @return A new empty transaction builder.
    [[nodiscard]] static auto emptyWithParams(
        const shelley::GenesisParameters& params
    ) -> TransactionBuilder;

    /// @brief Static method to populate a transaction buider from CBOR data.
    /// @param cbor_bytes Transaction CBOR data as a span of bytes.
    /// @return A new populated transaction builder.
    [[nodiscard]] static auto fromCBOR(std::span<const uint8_t> cbor_bytes
    ) -> TransactionBuilder;

    /// @brief Get the Era of the transaction builder.
    /// @return Era enum.
    [[nodiscard]] auto getEra() const -> Era { return era_; }

    /// @brief Add an input to the transaction.
    /// @param input The input UTxO.
    /// @return A reference to the transaction builder.
    auto addInput(const UTxO& input) -> TransactionBuilder&;

    /// @brief Add an output transaction.
    /// @param addr A base address object.
    /// @param amount The amount of the output in lovelaces.
    /// @return A reference to the transaction builder.
    auto addOutput(const BaseAddress& addr, uint64_t amount)
        -> TransactionBuilder&;

    /// @brief Add an output transaction.
    /// @param addr An enterprise address object.
    /// @param amount The amount of the output in lovelaces.
    /// @return A reference to the transaction builder.
    auto addOutput(const EnterpriseAddress& addr, uint64_t amount)
        -> TransactionBuilder&;

    /// @brief Add a rewards withdrawal to the transaction.
    /// @param addr A rewards address object.
    /// @param amount The amount to withdraw in lovelaces.
    /// @return A reference to the transaction builder.
    auto addWithdrawal(const RewardsAddress& addr, uint64_t amount)
        -> TransactionBuilder&;

    /// @brief Add a rewards address registration certificate to the
    /// transaction.
    /// @param addr A rewards address object.
    /// @param deposit Required deposit for credential registration.
    /// @return A reference to the transaction builder.
    auto addStakeRegistrationCertificate(
        const RewardsAddress& addr,
        uint64_t deposit
    ) -> TransactionBuilder&;

    /// @brief Add a rewards address deregistration certificate to the
    /// transaction.
    /// @param addr A rewards address object.
    /// @return A reference to the transaction builder.
    auto addStakeDeregistrationCertificate(const RewardsAddress& addr
    ) -> TransactionBuilder&;

    /// @brief Add a rewards address delegation certificate to the transaction.
    /// @param addr A rewards address object.
    /// @param pool_id The 28-byte ID of the selected stake pool.
    /// @return A reference to the transaction builder.
    auto addStakeDelegationCertificate(
        const RewardsAddress& addr,
        std::span<const uint8_t, stake_pool::STAKE_POOL_ID_SIZE> pool_id
    ) -> TransactionBuilder&;

    /// @brief Add a stake pool registration certificate to the transaction.
    ///
    /// Add a pre-built stake pool registration certificate to the transaction.
    /// Use a cardano::stake_pool::RegistrationCertificateManager to build the
    /// certificate. The certificate object is passed by value in order to move
    /// a copy into the transaction object managed by the transaction builder.
    /// Optionally specify a deposit (500000000 lovelaces) if this is an initial
    /// pool registration.
    ///
    /// @param cert The pre-built pool registration certificate.
    /// @param deposit Optional deposit if initial pool registration.
    /// @return A reference to the transaction builder.
    auto addPoolRegistrationCertificate(
        PoolRegistration cert,
        uint64_t deposit = 0
    ) -> TransactionBuilder&;

    /// @brief Add a stake pool retirement certificate to the transaction.
    ///
    /// Add a pre-built stake pool retirement certificate to the transaction.
    /// Use a cardano::stake_pool::RetirementCertificateManager to build the
    /// certificate. The certificate object is passed by value in order to move
    /// a copy into the transaction object managed by the transaction builder.
    ///
    /// @param cert The pre-built pool retirement certificate.
    /// @return A reference to the transaction builder.
    auto addPoolRetirementCertificate(PoolRetirement cert
    ) -> TransactionBuilder&;

    /// @brief Set the transaction fee.
    /// @param fee The transaction fee in lovelaces.
    /// @return A reference to the transaction builder.
    auto setFee(size_t fee) -> TransactionBuilder&;

    /// @brief Iteratively set and update the fee until steady state.
    /// @param numWitnesses Number of expected witnesses.
    /// @return A reference to the transaction builder.
    auto updateFee(uint32_t numWitnesses) -> TransactionBuilder&;

    /// @brief Set the transaction time to live.
    /// @param ttl The transaction time to live in slots.
    /// @return A reference to the transaction builder.
    auto setTtl(size_t ttl) -> TransactionBuilder&;

    /// @brief Set the transaction change address for balancing.
    /// @param addr An enterprise address object.
    /// @return A reference to the transaction builder.
    inline auto setChangeAddress(const EnterpriseAddress& addr
    ) -> TransactionBuilder&
    {
        this->change_addr_ = addr.toBytes();
        return *this;
    }

    /// @brief Set the transaction change address for balancing.
    /// @param addr An enterprise address object.
    /// @return A reference to the transaction builder.
    inline auto setChangeAddress(const BaseAddress& addr) -> TransactionBuilder&
    {
        this->change_addr_ = addr.toBytes();
        return *this;
    }

    /// @brief Compute the change and fee to balance the transaction.
    ///
    /// This function iteratively sets the fee and change values until the
    /// transaction is completely balanced. Note that this requires the
    /// transaction inputs to specify accurate value information. Additionally,
    /// a change address must be set. Dummy signatures will be added based on
    /// the provided number of expected witnesses in order to accurately
    /// calculate the transaction fees.
    ///
    /// This step should be executed just prior to final signature as modifying
    /// other transaction parameters may change the fees.
    ///
    /// @param numWitnesses Number of expected witnesses.
    /// @return A reference to the transaction builder.
    auto balance(uint32_t numWitnesses = 0) -> TransactionBuilder&;

    /// @brief Sign the transaction and add the signature to the witness set.
    /// @param skey An Ed25519 signing key.
    /// @return A reference to the transaction builder.
    auto sign(const ed25519::PrivateKey& skey) -> TransactionBuilder&;

    /// @brief Sign the transaction and add the signature to the witness set.
    /// @param skey A BIP32-Ed25519 signing key.
    /// @return A reference to the transaction builder.
    auto sign(const bip32_ed25519::PrivateKey& skey) -> TransactionBuilder&;

    /// @brief Remove all witnesses from the transaction witness set.
    auto clearWitnessSet() -> void;

    /// @brief Compute the transaction ID.
    /// @note The transaction ID is the hash (Blake2b256) of the transaction
    /// body CBOR. This ID is what is signed by the signing keys to signify
    /// transaction validity.
    [[nodiscard]] auto getID() const -> std::array<uint8_t, 32>;

    /// @brief Sign the transaction and return the signature.
    /// @param skey An Ed25519 signing key.
    /// @returns The signature as an array of bytes.
    [[nodiscard]] auto makeWitness(const ed25519::PrivateKey& skey
    ) -> std::array<uint8_t, ed25519::SIGNATURE_SIZE>;

    /// @brief Sign the transaction and return the signature.
    /// @param skey A BIP32-Ed25519 signing key.
    /// @returns The signature as an array of bytes.
    [[nodiscard]] auto makeWitness(const bip32_ed25519::PrivateKey& skey
    ) -> std::array<uint8_t, bip32_ed25519::SIGNATURE_SIZE>;

    /// @brief Serialize the transaction to a CBOR byte vector.
    /// @return The serialized transaction bytes.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>;

    /// @brief Calculate the transaction fee.
    ///
    /// The transaction must contain realistic values in all fields prior to the
    /// calculation. Dummy signatures will be added based on the provided number
    /// of expected witnesses. Note that this does not balance the transaction
    /// but only calculates the fees.
    ///
    /// @param numWitnesses Number of expected witnesses.
    /// @return A reference to the transaction builder.
    auto calculateFee(uint32_t numWitnesses = 0) -> uint64_t;

    /// @brief Return a constant reference to the transaction object.
    [[nodiscard]] const auto& getTransaction() const { return this->tx_; }

    /// @brief Set the value minFeeA for calculating transaction fees.
    /// @param new_min_fee_a The new value for minFeeA.
    inline auto setMinFeeA(int64_t new_min_fee_a) -> void
    {
        this->min_fee_a_ = new_min_fee_a;
    }

    /// @brief Set the value minFeeB for calculating transaction fees.
    /// @param new_min_fee_b The new value for minFeeB.
    inline auto setMinFeeB(int64_t new_min_fee_b) -> void
    {
        this->min_fee_b_ = new_min_fee_b;
    }

    /// @brief Access the minFeeA value used for transaction fee calculations.
    /// @return The minFeeA value.
    [[nodiscard]] inline auto getMinFeeA() const -> int64_t
    {
        return this->min_fee_a_;
    }

    /// @brief Access the minFeeB value used for transaction fee calculations.
    /// @return The minFeeB value.
    [[nodiscard]] inline auto getMinFeeB() const -> int64_t
    {
        return this->min_fee_b_;
    }
};  // TransactionBuilder

}  // namespace shelley

namespace babbage
{

/// @brief Build Babbage era Cardano transactions.
class TransactionBuilder
{
  private:
    // Set the era to that matching the version of the class.
    const Era era_ = Era::Babbage;

    // The transaction object that will be serialized to CBOR.
    babbage::Transaction tx_;

    // Optionally set the address to use for change when auto-balancing the
    // transaction.
    std::vector<uint8_t> change_addr_;

    // The minimum transaction fee coefficients. Default to those active within
    // the era but they are setable if needed.
    uint64_t min_fee_a_ = 44;
    uint64_t min_fee_b_ = 155381;

  public:
    /// @brief Construct a transaction builder object.
    TransactionBuilder() : tx_{babbage::Transaction{}} {};

    /// @brief Construct a transaction builder object from a Babbage era
    /// transaction structure.
    /// @param tx The transaction structure.
    explicit TransactionBuilder(babbage::Transaction tx) : tx_{std::move(tx)} {}

    /// @brief Static method to populate a transaction buider from CBOR data.
    /// @param cbor_bytes Transaction CBOR data as a span of bytes.
    /// @return A new transaction builder.
    [[nodiscard]] static auto fromCBOR(std::span<const uint8_t> cbor_bytes
    ) -> TransactionBuilder;

    /// @brief Get the Era of the transaction builder.
    /// @return Era enum.
    [[nodiscard]] auto getEra() const -> Era { return era_; }

    /// @brief Add an input to the transaction.
    /// @param id Transaction ID of the input UTxO.
    /// @param index Index of the input UTxO.
    /// @return A reference to the transaction builder.
    auto addInput(std::span<const uint8_t> id, uint64_t index)
        -> TransactionBuilder&;

    /// @brief Add an output transaction.
    /// @param addr A base address object.
    /// @param amount The amount of the output in lovelaces.
    /// @param prebabbage Use prebabbage CBOR structure (default: false).
    /// @return A reference to the transaction builder.
    auto addOutput(
        const BaseAddress& addr,
        uint64_t amount,
        bool prebabbage = false
    ) -> TransactionBuilder&;

    /// @brief Add an output transaction.
    /// @param addr An enterprise address object.
    /// @param amount The amount of the output in lovelaces.
    /// @param prebabbage Use prebabbage CBOR structure (default: false).
    /// @return A reference to the transaction builder.
    auto addOutput(
        const EnterpriseAddress& addr,
        uint64_t amount,
        bool prebabbage = false
    ) -> TransactionBuilder&;

    /// @brief Add a rewards withdrawal to the transaction.
    /// @param addr A rewards address object.
    /// @param amount The amount to withdraw in lovelaces.
    /// @return A reference to the transaction builder.
    auto addWithdrawal(const RewardsAddress& addr, uint64_t amount)
        -> TransactionBuilder&;

    auto addMint(
        const std::array<uint8_t, 32>& policy_id,
        std::vector<std::span<const uint8_t>> asset_names,
        std::vector<size_t> asset_counts
    ) -> TransactionBuilder&;

    /// @brief Set the transaction fee.
    /// @param fee The transaction fee in lovelaces.
    /// @return A reference to the transaction builder.
    auto setFee(size_t fee) -> TransactionBuilder&;

    /// @brief Set the transaction time to live.
    /// @param ttl The transaction time to live in slots.
    /// @return A reference to the transaction builder.
    auto setTtl(size_t ttl) -> TransactionBuilder&;

    /// @brief Set the transaction change address for balancing.
    /// @param addr An enterprise address object.
    /// @return A reference to the transaction builder.
    auto setChangeAddress(const EnterpriseAddress& addr) -> TransactionBuilder&
    {
        this->change_addr_ = addr.toBytes();
        return *this;
    }

    /// @brief Set the transaction change address for balancing.
    /// @param addr An enterprise address object.
    /// @return A reference to the transaction builder.
    auto setChangeAddress(const BaseAddress& addr) -> TransactionBuilder&
    {
        this->change_addr_ = addr.toBytes();
        return *this;
    }

    /// @brief Compute the change and fee to balance the transaction.
    ///
    /// This function iteratively sets the fee and change values until the
    /// transaction is completely balanced. Note that this requires the
    /// transaction inputs to specify accurate value information. Additionally,
    /// a change address must be set. Dummy signatures will be added based on
    /// the provided number of expected witnesses in order to accurately
    /// calculate the transaction fees.
    ///
    /// This step should be executed just prior to final signature as modifying
    /// other transaction parameters may change the fees.
    ///
    /// @param numWitnesses Number of expected witnesses.
    /// @return A reference to the transaction builder.
    auto balance(uint32_t numWitnesses = 0) -> TransactionBuilder&;

    /// @brief Sign the transaction and add the signature to the witness set.
    /// @param skey An Ed25519 signing key.
    /// @return A reference to the transaction builder.
    auto sign(const ed25519::PrivateKey& skey) -> TransactionBuilder&;

    /// @brief Sign the transaction and add the signature to the witness set.
    /// @param skey A BIP32-Ed25519 signing key.
    /// @return A reference to the transaction builder.
    auto sign(const bip32_ed25519::PrivateKey& skey) -> TransactionBuilder&;

    /// @brief Remove all witnesses from the transaction witness set.
    auto clearWitnessSet() -> void;

    /// @brief Compute the transaction ID.
    /// @note The transaction ID is the hash (Blake2b256) of the transaction
    /// body CBOR. This ID is what is signed by the signing keys to signify
    /// transaction validity.
    [[nodiscard]] auto getID() const -> std::array<uint8_t, 32>;

    /// @brief Sign the transaction and return the signature.
    /// @param skey An Ed25519 signing key.
    /// @returns The signature as an array of bytes.
    [[nodiscard]] auto makeWitness(const ed25519::PrivateKey& skey
    ) -> std::array<uint8_t, ed25519::SIGNATURE_SIZE>;

    /// @brief Sign the transaction and return the signature.
    /// @param skey A BIP32-Ed25519 signing key.
    /// @returns The signature as an array of bytes.
    [[nodiscard]] auto makeWitness(const bip32_ed25519::PrivateKey& skey
    ) -> std::array<uint8_t, bip32_ed25519::SIGNATURE_SIZE>;

    /// @brief Serialize the transaction to a CBOR byte vector.
    /// @return The serialized transaction bytes.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>;

    /// @brief Calculate the transaction fee.
    ///
    /// The transaction must contain realistic values in all fields prior to the
    /// calculation. Dummy signatures will be added based on the provided number
    /// of expected witnesses. Note that this does not balance the transaction
    /// but only calculates the fees.
    ///
    /// @param numWitnesses Number of expected witnesses.
    /// @return A reference to the transaction builder.
    auto calculateFee(uint32_t numWitnesses = 0) -> uint64_t;

    /// @brief Return a constant reference to the transaction object.
    [[nodiscard]] const auto& getTransaction() const { return this->tx_; }

    /// @brief Set the value minFeeA for calculating transaction fees.
    /// @param new_min_fee_a The new value for minFeeA.
    auto setMinFeeA(uint64_t new_min_fee_a) -> void
    {
        this->min_fee_a_ = new_min_fee_a;
    }

    /// @brief Set the value minFeeB for calculating transaction fees.
    /// @param new_min_fee_b The new value for minFeeB.
    auto setMinFeeB(uint64_t new_min_fee_b) -> void
    {
        this->min_fee_b_ = new_min_fee_b;
    }

    /// @brief Access the minFeeA value used for transaction fee calculations.
    /// @return The minFeeA value.
    [[nodiscard]] auto getMinFeeA() const -> uint64_t
    {
        return this->min_fee_a_;
    }

    /// @brief Access the minFeeB value used for transaction fee calculations.
    /// @return The minFeeB value.
    [[nodiscard]] auto getMinFeeB() const -> uint64_t
    {
        return this->min_fee_b_;
    }
};

}  // namespace babbage

using TransactionBuilder = babbage::TransactionBuilder;

}  // namespace cardano

#endif  // _CARDANO_TRANSACTION_HPP_