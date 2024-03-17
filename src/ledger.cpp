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

#include <cardano/ledger.hpp>

// Standard library headers

// Third-party library headers
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

// Private libcardano source
#include "utils.hpp"

using namespace cardano;

auto shelley::TransactionWitnessSet::serializer() const -> cppbor::Map
{
    auto witness_set = cppbor::Map{};
    if (vkeywitnesses)
    {
        auto vkeys_array = cppbor::Array{};
        for (auto const& [vkey, sige] : vkeywitnesses.value())
        {
            vkeys_array.add(cppbor::Array{
                cppbor::Bstr{{vkey.data(), vkey.size()}},
                cppbor::Bstr{{sige.data(), sige.size()}}
            });
        }
        witness_set.add(0, std::move(vkeys_array));
    }
    // do the same for multisig_script and bootstrap_witness
    return witness_set;
}  // shelley::TransactionWitnessSet::serializer

auto shelley::StakeRegistration::serializer() const -> cppbor::Array
{
    return cppbor::Array{cppbor::Uint(0), stake_credential.serializer()};
}

auto shelley::StakeDeregistration::serializer() const -> cppbor::Array
{
    return cppbor::Array{cppbor::Uint(1), stake_credential.serializer()};
}

auto shelley::StakeDelegation::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Uint(0),
        stake_credential.serializer(),
        cppbor::Bstr{{pool_keyhash.data(), pool_keyhash.size()}}
    };
}

auto shelley::PoolRegistration::serializer() const -> cppbor::Array
{
    auto cbor_serializer = cppbor::Array{
        cppbor::Uint(3),
        cppbor::Bstr{
            {pool_params.pool_operator.data(), pool_params.pool_operator.size()}
        },
        cppbor::Bstr{
            {pool_params.vrf_keyhash.data(), pool_params.vrf_keyhash.size()}
        },
        cppbor::Uint(pool_params.pledge),
        cppbor::Uint(pool_params.cost),
        pool_params.margin.serializer(),
        cppbor::Bstr{
            {pool_params.reward_account.data(),
             pool_params.reward_account.size()}
        },
    };

    if (!pool_params.pool_owners.empty())
    {
        auto pool_owners = cppbor::Array{};
        for (auto& owner : pool_params.pool_owners)
        {
            pool_owners.add(cppbor::Bstr{{owner.data(), owner.size()}});
        }
        cbor_serializer.add(std::move(pool_owners));
    }

    if (!pool_params.relays.empty())
    {
        auto relays = cppbor::Array{};
        for (auto& relay : pool_params.relays)
        {
            relays.add(relay->serializer());
        }
        cbor_serializer.add(std::move(relays));
    }

    if (pool_params.pool_metadata.has_value())
    {
        cbor_serializer.add(pool_params.pool_metadata.value().serializer());
    }

    return cbor_serializer;
}

auto shelley::PoolRetirement::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Uint(4),
        cppbor::Bstr{{pool_keyhash.data(), pool_keyhash.size()}},
        cppbor::Uint(epoch)
    };
}

auto shelley::GenesisKeyDelegation::serializer() const -> cppbor::Array
{
    return cppbor::Array{cppbor::Uint(5)};
}

auto shelley::MoveInstantaneousRewardsCert::serializer() const -> cppbor::Array
{
    return cppbor::Array{cppbor::Uint(6)};
}

auto shelley::TransactionOutput::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Bstr{{address.data(), address.size()}}, cppbor::Uint(amount)
    };
}

auto shelley::TransactionInput::serializer() const -> cppbor::Array
{
    return cppbor::Array{
        cppbor::Bstr{{transaction_id.data(), transaction_id.size()}},
        cppbor::Uint(index)
    };
}

///     transaction_body =
///       { 0 : set<transaction_input>
///       , 1 : [* transaction_output]
///       , 2 : coin ; fee
///       , 3 : uint ; ttl
///       , ? 4 : [* certificate]
///       , ? 5 : withdrawals
///       , ? 6 : update
///       , ? 7 : metadata_hash
///       }
// transaction_inputs = std::set<TransactionInput>{};
//         transaction_outputs = std::vector<TransactionOutput>{};
//         fee = Coin{};
//         ttl = 0;
//         certificates = std::nullopt;
//         withdrawals = std::nullopt;
//         update = std::nullopt;
//         metadata_hash = std::nullopt;
auto shelley::TransactionBody::serializer() const -> cppbor::Map
{
    auto tx_body = cppbor::Map{};

    auto tx_inputs = cppbor::Array{};
    for (auto const& input : transaction_inputs)
    {
        tx_inputs.add(input.serializer());
    }
    tx_body.add(0, std::move(tx_inputs));

    auto tx_outputs = cppbor::Array{};
    for (auto const& output : transaction_outputs)
    {
        tx_outputs.add(output.serializer());
    }
    tx_body.add(1, std::move(tx_outputs));

    tx_body.add(2, fee);
    tx_body.add(3, ttl);

    if (certificates)
    {
        // auto certificates_array = cppbor::Array{};
        // for (auto const& certificate : certificates.value())
        // {
        //     certificates_array.add(certificate->serializer());
        // }
        // transaction_body.add(4, std::move(certificates_array));
    }

    if (withdrawals)
    {
    }

    if (update)
    {
    }

    if (metadata_hash)
    {
    }

    return tx_body;
}  // shelley::TransactionBody::serializer

auto shelley::Transaction::serializer() const -> cppbor::Array
{
    auto transaction = cppbor::Array{
        transaction_body.serializer(), transaction_witness_set.serializer()
    };
    if (transaction_metadata)
    {
    }
    else
    {
        transaction.add(nullptr);
    }

    return transaction;
}  // shelley::Transaction::serializer

auto alonzo::TransactionOutput::serializer() const -> cppbor::Array
{
    auto tx_output = cppbor::Array(
        cppbor::Bstr{{address.data(), address.size()}}, cppbor::Uint(amount)
    );
    if (datum_hash)
    {
        tx_output.add(
            cppbor::Bstr{{datum_hash.value().data(), datum_hash.value().size()}}
        );
    }
    return tx_output;
};  // babbage::LegacyTransactionOutput::serializer

auto babbage::PostAlonzoTransactionOutput::serializer() const -> cppbor::Map
{
    auto tx_output = cppbor::Map();
    tx_output.add(0, cppbor::Bstr{{address.data(), address.size()}});
    tx_output.add(1, cppbor::Uint(amount));
    // TODO
    // if (datum_option) {}
    // if (script_ref) {}
    return tx_output;
};  // babbage::PostAlonzoTransactionOutput::serializer

auto babbage::TransactionBody::serializer() const -> cppbor::Map
{
    auto tx_body = cppbor::Map{};

    auto tx_inputs = cppbor::Array{};
    for (auto const& input : transaction_inputs)
    {
        tx_inputs.add(input.serializer());
    }
    tx_body.add(0, std::move(tx_inputs));

    auto tx_outputs = cppbor::Array{};
    for (auto const& output : transaction_outputs)
    {
        if (const auto pval =
                std::get_if<babbage::PreBabbageTransactionOutput>(&output))
        {
            tx_outputs.add(pval->serializer());
        }
        if (const auto pval =
                std::get_if<babbage::PostAlonzoTransactionOutput>(&output))
        {
            tx_outputs.add(pval->serializer());
        }
    }
    tx_body.add(1, std::move(tx_outputs));

    tx_body.add(2, fee);

    if (this->ttl)
    {
        tx_body.add(3, this->ttl.value());
    }

    //     if (certificates)
    //     {
    //         // auto certificates_array = cppbor::Array{};
    //         // for (auto const& certificate : certificates.value())
    //         // {
    //         //     certificates_array.add(certificate->serializer());
    //         // }
    //         // transaction_body.add(4, std::move(certificates_array));
    //     }
    //
    //     if (withdrawals)
    //     {
    //     }
    //
    //     if (update)
    //     {
    //     }
    //
    //     if (metadata_hash)
    //     {
    //     }

    return tx_body;
}  // babbage::TransactionBody::serializer

auto babbage::TransactionWitnessSet::serializer() const -> cppbor::Map
{
    auto witness_set = cppbor::Map{};
    if (!vkeywitnesses.empty())
    {
        auto vkeys_array = cppbor::Array{};
        for (auto const& [vkey, sige] : vkeywitnesses)
        {
            vkeys_array.add(cppbor::Array{
                cppbor::Bstr{{vkey.data(), vkey.size()}},
                cppbor::Bstr{{sige.data(), sige.size()}}
            });
        }
        witness_set.add(0, std::move(vkeys_array));
    }
    // do the same for multisig_script and bootstrap_witness
    return witness_set;
}  // babbage::TransactionWitnessSet::serializer

///       [ transaction_body
///       , transaction_witness_set
///       , bool
///       , auxiliary_data / null
///       ]
auto babbage::Transaction::serializer() const -> cppbor::Array
{
    auto tx = cppbor::Array(
        this->transaction_body.serializer(),
        this->transaction_witness_set.serializer(),
        cppbor::Bool(this->flag),
        nullptr
    );
    return tx;
}  // babbage::Transaction::serializer