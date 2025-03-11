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

using namespace cardano;

auto alonzo::TransactionOutput::serializer() const -> cppbor::Array
{
    auto tx_output = cppbor::Array();
    tx_output.add(cppbor::Bstr{{address.data(), address.size()}});
    tx_output.add(cppbor::Uint(amount));
    if (datum_hash)
    {
        tx_output.add(cppbor::Bstr{{datum_hash->data(), datum_hash->size()}});
    }
    return tx_output;
}  // babbage::LegacyTransactionOutput::serializer

auto babbage::ScriptRef::serializer() const -> cppbor::SemanticTag
{
    return cppbor::SemanticTag(24, cppbor::Bstr{script_cbor});
}  // babbage::ScriptRef::serializer

auto babbage::PostAlonzoTransactionOutput::serializer() const -> cppbor::Map
{
    auto tx_output = cppbor::Map();
    tx_output.add(0, cppbor::Bstr{{address.data(), address.size()}});
    tx_output.add(1, cppbor::Uint(amount));
    // TODO
    // if (datum_option) {}
    // if (script_ref) {}
    return tx_output;
}  // babbage::PostAlonzoTransactionOutput::serializer

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

    if (this->withdrawals.size() > 0)
    {
        auto withdrawals_cbor = cppbor::Map{};
        for (auto const& [addr, amount] : this->withdrawals)
        {
            withdrawals_cbor.add(cppbor::Bstr{addr}, cppbor::Uint(amount));
        }
        tx_body.add(5, std::move(withdrawals_cbor));
    }

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