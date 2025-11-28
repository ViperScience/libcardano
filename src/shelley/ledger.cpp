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

// Standard library headers
#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

// Third-party library headers
#include <cppbor/cppbor.h>

// Libcardano headers
#include <cardano/ledger.hpp>
#include <cardano/util.hpp>

namespace cardano::shelley
{

auto PoolMetadata::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Tstr(url), cppbor::Bstr{{hash.data(), hash.size()}}
    };
}  // PoolMetadata::serializer

void PoolMetadata::deserializer(const cppbor::Array& data)
{
    if (!data.asArray())
    {
        throw std::runtime_error("PoolMetadata data must be a CBOR array");
    }

    const auto arr = data.asArray();
    if (arr->size() != 2)
    {
        throw std::runtime_error(
            "PoolMetadata CBOR array must have exactly 2 elements"
        );
    }

    if (!(arr->get(0)->asTstr()) || !(arr->get(1)->asBstr()))
    {
        throw std::runtime_error(
            "PoolMetadata CBOR elements are not the expected types"
        );
    }

    this->url = arr->get(0)->asTstr()->value();

    const auto cbor_hash = arr->get(1)->asBstr()->value();
    if (cbor_hash.size() != 32)
    {
        throw std::invalid_argument(
            "Invalid data size: expected 32 bytes, got " + std::to_string(cbor_hash.size())
        );
    }
    std::copy_n(cbor_hash.begin(), 32, this->hash.begin());
}

auto Relay::serializer() const -> cppbor::Array
{
    auto arr = cppbor::Array{};
    std::visit(
        [&arr](auto&& arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, SingleHostAddr>)
            {
                arr.add(SingleHostAddr::TypeTag());
                if (arg.port.has_value())
                {
                    arr.add(cppbor::Uint(arg.port.value()));
                }
                else
                {
                    arr.add(cppbor::Null());
                }
                if (arg.ipv4.has_value())
                {
                    arr.add(cppbor::Bstr(
                        {arg.ipv4.value().data(), arg.ipv4.value().size()}
                    ));
                    arr.add(cppbor::Null());
                }
                else if (arg.ipv6.has_value())
                {
                    arr.add(cppbor::Null());
                    arr.add(cppbor::Bstr(
                        {arg.ipv6.value().data(), arg.ipv4.value().size()}
                    ));
                }
            }
            else if constexpr (std::is_same_v<T, SingleHostName>)
            {
                arr.add(SingleHostName::TypeTag());
                if (arg.port.has_value())
                {
                    arr.add(cppbor::Uint(arg.port.value()));
                }
                else
                {
                    arr.add(cppbor::Null());
                }
                arr.add(cppbor::Tstr(arg.dns_name));
            }
            else if constexpr (std::is_same_v<T, MultiHostName>)
            {
                arr.add(MultiHostName::TypeTag());
                arr.add(cppbor::Tstr(arg.dns_name));
            }
        },
        this->relay
    );
    return arr;
}  // Relay::serializer

auto Relay::deserializer(const cppbor::Array& data) -> void
{
    if ((data.size() < 2) || !(data.get(0)->asUint()))
    {
        throw std::runtime_error("Relay data must be a CBOR array");
    }
    switch (data.get(0)->asUint()->unsignedValue())
    {
        case SingleHostAddr::TypeTag():
        {
            if (!(data.size() == 4) || !(data.get(0)->asUint()))
            {
                throw std::runtime_error(
                    "SingleHostAddr CBOR elements are not the expected types"
                );
            }
            if (data.get(0)->asUint()->value() != SingleHostAddr::TypeTag())
            {
                throw std::runtime_error(
                    "The CBOR does not contain valid SingleHostAddr relay data"
                );
            }
            auto r = SingleHostAddr{};
            if (data.get(1)->asUint())
            {
                r.port = static_cast<Port>(data.get(1)->asUint()->value());
            }
            if (data.get(2)->asBstr() &&
                (data.get(2)->asBstr()->value().size() == 4))
            {
                auto ip = IPV4{};
                const auto ip_bytes = data.get(2)->asBstr()->value();
                if (ip_bytes.size() != 4)
                {
                    throw std::invalid_argument("Expected 4 bytes for IPv4 addr.");
                }
                std::copy_n(ip_bytes.begin(), 4, ip.begin());
                r.ipv4 = ip;
            }
            else if (data.get(2)->asBstr() &&
                     (data.get(2)->asBstr()->value().size() == 16))
            {
                auto ip = IPV6{};
                const auto ip_bytes = data.get(2)->asBstr()->value();
                if (ip_bytes.size() != 16)
                {
                    throw std::invalid_argument("Expected 16 bytes for IPv6 addr.");
                }
                std::copy_n(ip_bytes.begin(), 16, ip.begin());
                r.ipv6 = ip;
            }
            this->relay = std::move(r);
            break;
        }
        case SingleHostName::TypeTag():
        {
            if (!(data.size() == 3) || !(data.get(0)->asUint()) ||
                !(data.get(2)->asTstr()))
            {
                throw std::runtime_error(
                    "SingleHostName CBOR elements are not the expected types"
                );
            }
            if (data.get(0)->asUint()->value() != SingleHostName::TypeTag())
            {
                throw std::runtime_error(
                    "The CBOR does not contain valid SingleHostName relay data"
                );
            }
            auto r = SingleHostName{};
            if (data.get(1)->asUint())
            {
                r.port = static_cast<Port>(data.get(1)->asUint()->value());
            }
            r.dns_name = data.get(2)->asTstr()->value();
            this->relay = std::move(r);
            break;
        }
        case MultiHostName::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asTstr()))
            {
                throw std::runtime_error(
                    "MultiHostName CBOR elements are not the expected types"
                );
            }
            if (data.get(0)->asUint()->value() != MultiHostName::TypeTag())
            {
                throw std::runtime_error(
                    "The CBOR does not contain valid MultiHostName relay data"
                );
            }
            auto r = MultiHostName{};
            r.dns_name = data.get(1)->asTstr()->value();
            this->relay = std::move(r);
            break;
        }
        default:
        {
            break;  // Should never reach this
        }
    }
}  // Relay::deserializer

auto StakeCredential::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Uint(type), cppbor::Bstr{{cred.data(), cred.size()}}
    };
}  // StakeCredential::serializer

auto StakeCredential::deserializer(const cppbor::Array& data) -> void
{
    if (!data.asArray() || (data.asArray()->size() != 2))
    {
        throw std::runtime_error(
            "TransactionOutput data must be a 2-element CBOR array"
        );
    }
    const auto cbor_array = data.asArray();

    if (!(cbor_array->get(0)->asUint()) || !(cbor_array->get(1)->asBstr()))
    {
        throw std::runtime_error(
            "MoveInstantaneousReward CBOR elements are not the expected types"
        );
    }

    const auto cbor_type_id = cbor_array->get(0)->asUint()->value();
    switch (cbor_type_id)
    {
        case 0:
            this->type = Type::addr_keyhash;
            break;
        case 1:
            this->type = Type::scripthash;
            break;
        default:
            throw std::runtime_error("Invalid stake credential type.");
    }

    const auto cbor_cred = cbor_array->get(1)->asBstr()->value();
    if (cbor_cred.size() != 28)
    {
        throw std::invalid_argument(
            "Invalid data size: expected 28 bytes, got " + std::to_string(cbor_cred.size())
        );
    }
    std::copy_n(cbor_cred.begin(), 28, this->cred.begin());
}  // StakeCredential::deserializer

auto MoveInstantaneousReward::serializer() const -> cppbor::Array
{
    auto cbor_array = cppbor::Array{cppbor::Uint(this->source)};
    auto creds_cbor_map = cppbor::Map{};
    for (const auto& cred : this->stake_credentials)
    {
        creds_cbor_map.add(cred.first.serializer(), cppbor::Uint(cred.second));
    }
    cbor_array.add(std::move(creds_cbor_map));
    return cbor_array;
}  // MoveInstantaneousReward::serializer

auto MoveInstantaneousReward::deserializer(const cppbor::Array& data) -> void
{
    if (!data.asArray() || (data.asArray()->size() != 2))
    {
        throw std::runtime_error(
            "TransactionOutput data must be a 2-element CBOR array"
        );
    }
    const auto cbor_array = data.asArray();

    if (!(cbor_array->get(0)->asUint()) || !(cbor_array->get(1)->asMap()))
    {
        throw std::runtime_error(
            "MoveInstantaneousReward CBOR elements are not the expected types"
        );
    }

    const auto cbor_source_id = cbor_array->get(0)->asUint()->value();
    switch (cbor_source_id)
    {
        case 0:
            this->source = RewardSource::reserves;
            break;
        case 1:
            this->source = RewardSource::treasury;
            break;
        default:
            throw std::runtime_error("Invalid reward source.");
    }

    const auto cred_map = cbor_array->get(1)->asMap();
    for (auto it = cred_map->begin(); it != cred_map->end(); ++it)
    {
        auto cred = StakeCredential{};
        cred.deserializer(*((*it).first->asArray()));
        this->stake_credentials.push_back(
            std::make_pair(cred, (*it).second->asUint()->value())
        );
    }
}  // MoveInstantaneousReward::deserializer

auto Certificate::serializer() const -> cppbor::Array
{
    auto arr = cppbor::Array{};
    std::visit(
        [&arr](auto&& arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, StakeRegistration>)
            {
                arr.add(StakeRegistration::TypeTag());
                arr.add(arg.stake_credential.serializer());
            }
            else if constexpr (std::is_same_v<T, StakeDeregistration>)
            {
                arr.add(StakeDeregistration::TypeTag());
                arr.add(arg.stake_credential.serializer());
            }
            else if constexpr (std::is_same_v<T, StakeDelegation>)
            {
                arr.add(StakeDelegation::TypeTag());
                arr.add(arg.stake_credential.serializer());
                arr.add(cppbor::Bstr{
                    {arg.pool_keyhash.data(), arg.pool_keyhash.size()}
                });
            }
            else if constexpr (std::is_same_v<T, PoolRegistration>)
            {
                arr.add(PoolRegistration::TypeTag());
                arr.add(cppbor::Bstr{
                    {arg.pool_params.pool_operator.data(),
                     arg.pool_params.pool_operator.size()}
                });
                arr.add(cppbor::Bstr{
                    {arg.pool_params.vrf_keyhash.data(),
                     arg.pool_params.vrf_keyhash.size()}
                });
                arr.add(arg.pool_params.pledge);
                arr.add(arg.pool_params.cost);
                arr.add(arg.pool_params.margin.serializer());
                arr.add(cppbor::Bstr{
                    {arg.pool_params.reward_account.data(),
                     arg.pool_params.reward_account.size()}
                });
                if (!arg.pool_params.pool_owners.empty())
                {
                    auto pool_owners = cppbor::Array{};
                    for (auto& owner : arg.pool_params.pool_owners)
                    {
                        pool_owners.add(
                            cppbor::Bstr{{owner.data(), owner.size()}}
                        );
                    }
                    arr.add(std::move(pool_owners));
                }
                if (!arg.pool_params.relays.empty())
                {
                    auto relays = cppbor::Array{};
                    for (auto& relay : arg.pool_params.relays)
                    {
                        relays.add(relay.serializer());
                    }
                    arr.add(std::move(relays));
                }
                if (arg.pool_params.pool_metadata.has_value())
                {
                    arr.add(arg.pool_params.pool_metadata.value().serializer());
                }
            }
            else if constexpr (std::is_same_v<T, PoolRetirement>)
            {
                arr.add(PoolRetirement::TypeTag());
                arr.add(cppbor::Bstr{
                    {arg.pool_keyhash.data(), arg.pool_keyhash.size()}
                });
                arr.add(arg.epoch);
            }
            else if constexpr (std::is_same_v<T, GenesisKeyDelegation>)
            {
                arr.add(GenesisKeyDelegation::TypeTag());
                arr.add(cppbor::Bstr{
                    {arg.genesishash.data(), arg.genesishash.size()}
                });
                arr.add(cppbor::Bstr{
                    {arg.genesis_delegate_hash.data(),
                     arg.genesis_delegate_hash.size()}
                });
                arr.add(cppbor::Bstr{
                    {arg.vrf_keyhash.data(), arg.vrf_keyhash.size()}
                });
            }
            else if constexpr (std::is_same_v<T, MoveInstantaneousRewardsCert>)
            {
                arr.add(MoveInstantaneousRewardsCert::TypeTag());
                arr.add(arg.move_instantaneous_reward.serializer());
            }
            else
            {
                // Do nothing. Invalid certificate type.
            }
        },
        this->certificate
    );
    return arr;
}  // Certificate::serializer

auto Certificate::deserializer(const cppbor::Array& data) -> void
{
    if ((data.size() < 2) || !(data.get(0)->asUint()))
    {
        throw std::runtime_error("Certificate data must be a CBOR array");
    }

    switch (data.get(0)->asUint()->unsignedValue())
    {
        case StakeRegistration::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asArray()))
            {
                throw std::runtime_error(
                    "StakeRegistration CBOR elements are not the expected types"
                );
            }
            auto cert = StakeRegistration{};
            cert.stake_credential.deserializer(*(data.get(1)->asArray()));
            this->certificate = std::move(cert);
            break;
        }
        case StakeDeregistration::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asArray()))
            {
                throw std::runtime_error(
                    "StakeDeregistration CBOR elements are not the expected types"
                );
            }
            auto cert = StakeDeregistration{};
            cert.stake_credential.deserializer(*(data.get(1)->asArray()));
            this->certificate = std::move(cert);
            break;
        }
        case StakeDelegation::TypeTag():
        {
            if (!(data.size() == 3) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asArray()) || !(data.get(2)->asBstr()))
            {
                throw std::runtime_error(
                    "StakeDelegation CBOR elements are not the expected types"
                );
            }
            auto cert = StakeDelegation{};
            cert.stake_credential.deserializer(*(data.get(1)->asArray()));
            const auto hash_bytes = data.get(2)->asBstr()->value();
            if (hash_bytes.size() != 28)
            {
                throw std::invalid_argument("Expected 28 bytes for hash.");
            }
            std::copy_n(hash_bytes.begin(), 28, cert.pool_keyhash.begin());
            this->certificate = std::move(cert);
            break;
        }
        case PoolRegistration::TypeTag():
        {
            if ((data.size() < 7) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asBstr()) || !(data.get(2)->asBstr()) ||
                !(data.get(3)->asUint()) || !(data.get(4)->asUint()) ||
                !(data.get(5)->asArray()) || !(data.get(6)->asBstr()))
            {
                throw std::invalid_argument(
                    "PoolRegistration CBOR elements are not the expected types"
                );
            }
            auto params = PoolParams{};
            if (data.get(1)->asBstr()->value().size() != params.pool_operator.size())
            {
                throw std::invalid_argument("Unexpected number of bytes.");
            }
            std::copy_n(
                data.get(1)->asBstr()->value().begin(),
                params.pool_operator.size(),
                params.pool_operator.begin()
            );
            if (data.get(2)->asBstr()->value().size() != params.vrf_keyhash.size())
            {
                throw std::invalid_argument("Unexpected number of bytes.");
            }
            std::copy_n(
                data.get(2)->asBstr()->value().begin(),
                params.vrf_keyhash.size(),
                params.vrf_keyhash.begin()
            );
            params.pledge = data.get(3)->asUint()->unsignedValue();
            params.cost = data.get(4)->asUint()->unsignedValue();
            params.margin.deserializer(*(data.get(5)->asSemanticTag()));
            params.reward_account = data.get(6)->asBstr()->value();
            if (data.size() > 7 && data.get(7)->asArray())
            {
                const auto arr = data.get(7)->asArray();
                for (auto it = arr->begin(); it != arr->end(); ++it)
                {
                    auto owner = AddrKeyHash{};
                    if ((*it)->asBstr()->value().size() != owner.size())
                    {
                        throw std::invalid_argument("Invalid key hash size.");
                    }
                    std::copy_n(
                        (*it)->asBstr()->value().begin(),
                        owner.size(),
                        owner.begin()
                    );
                    params.pool_owners.insert(std::move(owner));
                }
            }
            if (data.size() > 8 && data.get(8)->asArray())
            {
                const auto arr = data.get(8)->asArray();
                for (auto it = arr->begin(); it != arr->end(); ++it)
                {
                    // TODO
                }
            }
            if (data.size() > 9)
            {
                // TODO
            }
            auto cert = PoolRegistration{};
            cert.pool_params = std::move(params);
            this->certificate = std::move(cert);
            break;
        }
        case PoolRetirement::TypeTag():
        {
            if (!(data.size() == 3) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asBstr()) || !(data.get(2)->asUint()))
            {
                throw std::runtime_error(
                    "PoolRetirement CBOR elements are not the expected types"
                );
            }
            auto cert = PoolRetirement{};
            const auto hash_bytes = data.get(1)->asBstr()->value();
            if (hash_bytes.size() != cert.pool_keyhash.size())
            {
                throw std::runtime_error("Invalid size for pool key hash.");
            }
            std::copy_n(
                hash_bytes.begin(),
                cert.pool_keyhash.size(),
                cert.pool_keyhash.begin()
            );
            cert.epoch = data.get(2)->asUint()->unsignedValue();
            this->certificate = std::move(cert);
            break;
        }
        case GenesisKeyDelegation::TypeTag():
        {
            auto cert = GenesisKeyDelegation{};
            if (data.get(0)->asBstr()->value().size() != cert.genesishash.size())
            {
                throw std::invalid_argument("Unexpected number of bytes.");
            }
            std::copy_n(
                data.get(0)->asBstr()->value().begin(),
                cert.genesishash.size(),
                cert.genesishash.begin()
            );
            if (data.get(1)->asBstr()->value().size() != cert.genesis_delegate_hash.size())
            {
                throw std::invalid_argument("Unexpected number of bytes.");
            }
            std::copy_n(
                data.get(1)->asBstr()->value().begin(),
                cert.genesis_delegate_hash.size(),
                cert.genesis_delegate_hash.begin()
            );
            if (data.get(2)->asBstr()->value().size() != cert.vrf_keyhash.size())
            {
                throw std::invalid_argument("Unexpected number of bytes.");
            }
            std::copy_n(
                data.get(2)->asBstr()->value().begin(),
                cert.vrf_keyhash.size(),
                cert.vrf_keyhash.begin()
            );
            this->certificate = std::move(cert);
            break;
        }
        case MoveInstantaneousRewardsCert::TypeTag():
        {
            auto cert = MoveInstantaneousRewardsCert{};
            cert.move_instantaneous_reward.deserializer(*(data.get(1)->asArray()
            ));
            this->certificate = std::move(cert);
            break;
        }
        default:
        {
            break;  // Should never reach this
        }
    }
}  // Certificate::deserializer

auto TransactionOutput::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Bstr{{address.data(), address.size()}}, cppbor::Uint(amount)
    };
}  // TransactionOutput::serializer

auto TransactionOutput::deserializer(const cppbor::Array& data) -> void
{
    if (!data.asArray())
    {
        throw std::runtime_error("TransactionOutput data must be a CBOR array");
    }

    if (data.asArray()->size() != 2)
    {
        throw std::runtime_error(
            "TransactionOutput CBOR array must have exactly 2 elements"
        );
    }

    const auto cbor_array = data.asArray();
    if (!(cbor_array->get(0)->asBstr()) || !(cbor_array->get(1)->asUint()))
    {
        throw std::runtime_error(
            "TransactionOutput CBOR elements are not the expected types"
        );
    }

    this->address = cbor_array->get(0)->asBstr()->value();
    this->amount = cbor_array->get(1)->asUint()->unsignedValue();
}  // TransactionOutput::deserializer

auto TransactionInput::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Bstr{{transaction_id.data(), transaction_id.size()}},
        cppbor::Uint(index)
    };
}  // TransactionInput::serializer

auto TransactionInput::deserializer(const cppbor::Array& data) -> void
{
    if (!data.asArray())
    {
        throw std::invalid_argument("TransactionInput data must be a CBOR array");
    }

    if (data.asArray()->size() != 2)
    {
        throw std::invalid_argument(
            "TransactionInput CBOR array must have exactly 2 elements"
        );
    }

    const auto cbor_array = data.asArray();

    if (!(cbor_array->get(0)->asBstr()) || !(cbor_array->get(1)->asUint()))
    {
        throw std::invalid_argument(
            "TransactionInput CBOR elements are not the expected types"
        );
    }

    const auto tx_id = cbor_array->get(0)->asBstr()->value();
    if (tx_id.size() != 32) {
        throw std::invalid_argument("Expected 32 bytes.");
    }
    std::copy_n(tx_id.begin(), 32, this->transaction_id.begin());
    this->index = cbor_array->get(1)->asUint()->unsignedValue();
}  // TransactionInput::deserializer

auto MultisigScript::serializer() const -> cppbor::Array
{
    auto arr = cppbor::Array{};
    std::visit(
        [&arr](auto&& arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::shared_ptr<MultisigPubkey>>)
            {
                arr.add(MultisigPubkey::TypeTag());
                arr.add(cppbor::Bstr{
                    {arg->addr_keyhash.data(), arg->addr_keyhash.size()}
                });
            }
            else if constexpr (std::is_same_v<T, std::shared_ptr<MultisigAll>>)
            {
                arr.add(MultisigAll::TypeTag());
                auto scripts_arr = cppbor::Array{};
                for (const auto& s : arg->scripts)
                {
                    scripts_arr.add(s.serializer());
                }
                arr.add(std::move(scripts_arr));
            }
            else if constexpr (std::is_same_v<T, std::shared_ptr<MultisigAny>>)
            {
                arr.add(MultisigAny::TypeTag());
                auto scripts_arr = cppbor::Array{};
                for (const auto& s : arg->scripts)
                {
                    scripts_arr.add(s.serializer());
                }
                arr.add(std::move(scripts_arr));
            }
            else if constexpr (std::is_same_v<T, std::shared_ptr<MultisigNofK>>)
            {
                arr.add(MultisigNofK::TypeTag());
                arr.add(arg->n);
                auto scripts_arr = cppbor::Array{};
                for (const auto& s : arg->scripts)
                {
                    scripts_arr.add(s.serializer());
                }
                arr.add(std::move(scripts_arr));
            }
            else
            {
                // Do nothing. Invalid certificate type.
            }
        },
        this->script
    );
    return arr;
}  // MultisigScript::serializer

auto MultisigScript::deserializer(const cppbor::Array& data) -> void
{
    if ((data.size() < 2) || !(data.get(0)->asUint()))
    {
        throw std::invalid_argument("MultisigScript data must be a CBOR array");
    }

    switch (data.get(0)->asUint()->unsignedValue())
    {
        case MultisigPubkey::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asBstr()))
            {
                throw std::invalid_argument(
                    "MultisigPubkey CBOR elements are not the expected types"
                );
            }
    
            auto msig = MultisigPubkey{};
            const auto msig_bytes = data.get(1)->asBstr()->value();
            if (msig_bytes.size() != msig.addr_keyhash.size())
            {
                throw std::invalid_argument("Invalid address key hash size");
            }
            std::copy_n(
                msig_bytes.begin(),
                msig.addr_keyhash.size(),
                msig.addr_keyhash.begin()
            );
            this->script = std::make_shared<MultisigPubkey>(std::move(msig));
            break;
        }
        case MultisigAll::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asArray()))
            {
                throw std::runtime_error(
                    "MultisigAll CBOR elements are not the expected types"
                );
            }
            auto msig = MultisigAll{};
            for (auto it = data.get(1)->asArray()->begin();
                 it != data.get(1)->asArray()->end();
                 ++it)
            {
                auto s = MultisigScript{};
                s.deserializer(*((*it)->asArray()));
                msig.scripts.push_back(std::move(s));
            }
            this->script = std::make_shared<MultisigAll>(std::move(msig));
            break;
        }
        case MultisigAny::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asArray()))
            {
                throw std::runtime_error(
                    "MultisigAll CBOR elements are not the expected types"
                );
            }
            auto msig = MultisigAny{};
            for (auto it = data.get(1)->asArray()->begin();
                 it != data.get(1)->asArray()->end();
                 ++it)
            {
                auto s = MultisigScript{};
                s.deserializer(*((*it)->asArray()));
                msig.scripts.push_back(std::move(s));
            }
            this->script = std::make_shared<MultisigAny>(std::move(msig));
            break;
        }
        case MultisigNofK::TypeTag():
        {
            if (!(data.size() == 2) || !(data.get(0)->asUint()) ||
                !(data.get(1)->asUint()) || !(data.get(2)->asArray()))
            {
                throw std::runtime_error(
                    "PoolRegistration CBOR elements are not the expected types"
                );
            }
            auto msig = MultisigNofK{};
            msig.n = data.get(1)->asUint()->unsignedValue();
            for (auto it = data.get(2)->asArray()->begin();
                 it != data.get(1)->asArray()->end();
                 ++it)
            {
                auto s = MultisigScript{};
                s.deserializer(*((*it)->asArray()));
                msig.scripts.push_back(std::move(s));
            }
            this->script = std::make_shared<MultisigNofK>(std::move(msig));
            break;
        }
        default:
        {
            break;  // Should never reach this
        }
    }
}  // MultisigScript::deserializer

auto TransactionBody::serializer() const -> cppbor::Map
{
    auto tx_body = cppbor::Map{};

    auto tx_inputs = cppbor::Array{};
    for (auto const& input : this->transaction_inputs)
    {
        tx_inputs.add(input.serializer());
    }
    tx_body.add(0, std::move(tx_inputs));

    auto tx_outputs = cppbor::Array{};
    for (auto const& output : this->transaction_outputs)
    {
        tx_outputs.add(output.serializer());
    }
    tx_body.add(1, std::move(tx_outputs));

    tx_body.add(2, this->fee);
    tx_body.add(3, this->ttl);

    if (this->certificates.size() > 0)
    {
        auto cert_array = cppbor::Array{};
        for (auto const& cert : certificates)
        {
            cert_array.add(cert.serializer());
        }
        tx_body.add(4, std::move(cert_array));
    }

    if (this->withdrawals.size() > 0)
    {
        auto withdrawals_cbor = cppbor::Map{};
        for (auto const& [addr, amount] : this->withdrawals)
        {
            withdrawals_cbor.add(cppbor::Bstr{addr}, cppbor::Uint(amount));
        }
        tx_body.add(5, std::move(withdrawals_cbor));
    }

    if (update)
    {
    }

    if (metadata_hash)
    {
        tx_body.add(
            7,
            cppbor::Bstr(
                {(*this->metadata_hash).data(), (*this->metadata_hash).size()}
            )
        );
    }

    return tx_body;
}  // TransactionBody::serializer

auto TransactionBody::deserializer(const cppbor::Map& data) -> void
{
    if (!data.asMap())
    {
        throw std::runtime_error("TransactionBody data must be a CBOR map");
    }
    const auto cbor_map = data.asMap();

    // Transaction input set
    this->transaction_inputs.clear();
    if (cbor_map->get(0) && cbor_map->get(0)->asArray())
    {
        const auto input_arr = cbor_map->get(0)->asArray();
        for (auto it = input_arr->begin(); it != input_arr->end(); ++it)
        {
            auto input = shelley::TransactionInput{};
            input.deserializer(*((*it)->asArray()));
            this->transaction_inputs.insert(std::move(input));
        }
    }

    // Transaction outputs
    this->transaction_outputs.clear();
    if (cbor_map->get(1) && cbor_map->get(1)->asArray())
    {
        const auto output_arr = cbor_map->get(1)->asArray();
        for (auto it = output_arr->begin(); it != output_arr->end(); ++it)
        {
            auto output = shelley::TransactionOutput{};
            output.deserializer(*((*it)->asArray()));
            this->transaction_outputs.push_back(output);
        }
    }

    // Transaction fee
    this->fee = 0;
    if (cbor_map->get(2) && cbor_map->get(2)->asUint())
    {
        this->fee = cbor_map->get(2)->asUint()->unsignedValue();
    }

    // Time-to-live
    this->ttl = 0;
    if (cbor_map->get(3) && cbor_map->get(3)->asUint())
    {
        this->ttl = cbor_map->get(3)->asUint()->unsignedValue();
    }

    // Certificates
    this->certificates.clear();
    if (cbor_map->get(4) && cbor_map->get(4)->asArray())
    {
        const auto cert_arr = cbor_map->get(4)->asArray();
        for (auto it = cert_arr->begin(); it != cert_arr->end(); ++it)
        {
            auto cert = Certificate{};
            cert.deserializer(*((*it)->asArray()));
            this->certificates.push_back(cert);
        }
    }

    // Withdrawals
    this->withdrawals.clear();
    if (cbor_map->get(5) && cbor_map->get(5)->asMap())
    {
        const auto withdrawals_cbor = cbor_map->get(5)->asMap();
        for (auto it = withdrawals_cbor->begin(); it != withdrawals_cbor->end();
             ++it)
        {
            const auto address = (*it).first->asBstr()->value();
            const auto amount = (*it).second->asUint()->unsignedValue();
            this->withdrawals[address] = amount;
        }
    }

    // Paramater Updates
    this->update.reset();
    if (cbor_map->get(6) && cbor_map->get(6)->asArray())
    {
        // TODO
    }

    // Metadata Hash
    this->metadata_hash.reset();
    if (cbor_map->get(7) && cbor_map->get(7)->asBstr())
    {
        auto bytes = Hash32{};
        const auto deser_bytes = cbor_map->get(7)->asBstr()->value();
        if (deser_bytes.size() != 32)
        {
            throw std::invalid_argument("Expected 32 bytes for hash.");
        }
        std::copy_n(deser_bytes.begin(), 32, bytes.begin());
        this->metadata_hash = bytes;
    }

}  // TransactionBody::deserializer

auto TransactionWitnessSet::serializer() const -> cppbor::Map
{
    auto witness_set = cppbor::Map{};
    if (this->vkeywitnesses.size() > 0)
    {
        auto vkeys_array = cppbor::Array{};
        for (auto const& [vkey, sign] : this->vkeywitnesses)
        {
            vkeys_array.add(cppbor::Array{
                cppbor::Bstr{{vkey.data(), vkey.size()}},
                cppbor::Bstr{{sign.data(), sign.size()}}
            });
        }
        witness_set.add(0, std::move(vkeys_array));
    }
    if (this->multisig_scripts.size() > 0)
    {
        auto scripts_array = cppbor::Array{};
        for (auto const& script : this->multisig_scripts)
        {
            scripts_array.add(script.serializer());
        }
        witness_set.add(1, std::move(scripts_array));
    }
    if (this->bootstrap_witnesses.size() > 0)
    {
        auto bootstrap_array = cppbor::Array{};
        // TODO
        witness_set.add(2, std::move(bootstrap_array));
    }
    return witness_set;
}  // TransactionWitnessSet::serializer

auto TransactionWitnessSet::deserializer(const cppbor::Map& data) -> void
{
    if (!data.asMap())
    {
        throw std::runtime_error("TransactionWitnessSet data must be a CBOR map"
        );
    }
    const auto cbor_map = data.asMap();

    this->vkeywitnesses.clear();
    if (cbor_map->get(0) && cbor_map->get(0)->asArray())
    {
        const auto vkeywit_arr = cbor_map->get(0)->asArray();
        for (auto it = vkeywit_arr->begin(); it != vkeywit_arr->end(); ++it)
        {
            const auto vkeywit = (*it)->asArray();
            if (vkeywit)
            {
                this->vkeywitnesses.push_back(
                    {cardano::util::makeByteArray<32>(
                         vkeywit->get(0)->asBstr()->value()
                     ),
                     cardano::util::makeByteArray<64>(
                         vkeywit->get(1)->asBstr()->value()
                     )}
                );
            }
        }
    }

    this->multisig_scripts.clear();
    if (cbor_map->get(1) && cbor_map->get(1)->asArray())
    {
        // TODO
    }

    this->bootstrap_witnesses.clear();
    if (cbor_map->get(2) && cbor_map->get(2)->asArray())
    {
        // TODO
    }
}  // TransactionWitnessSet::deserializer

auto Transaction::serializer() const -> cppbor::Array
{
    auto transaction = cppbor::Array{
        this->transaction_body.serializer(),
        this->transaction_witness_set.serializer()
    };
    if (transaction_metadata)
    {
    }
    else
    {
        transaction.add(nullptr);
    }
    return transaction;
}  // Transaction::serializer

auto Transaction::deserializer(const cppbor::Array& data) -> void
{
    if (!data.asArray())
    {
        throw std::runtime_error("Transaction data must be a CBOR array");
    }
    const auto cbor_arr = data.asArray();

    if ((cbor_arr->size() > 0) && cbor_arr->get(0)->asMap())
    {
        const auto tx_body_cbor = cbor_arr->get(0)->asMap();
        this->transaction_body.deserializer(*tx_body_cbor);
    }

    if ((cbor_arr->size() > 1) && cbor_arr->get(1)->asMap())
    {
        const auto tx_witnesses_cbor = cbor_arr->get(1)->asMap();
        this->transaction_witness_set.deserializer(*tx_witnesses_cbor);
    }

    // TODO: metadata...

}  // Transaction::deserializer

}  // namespace cardano::shelley