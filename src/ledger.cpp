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
