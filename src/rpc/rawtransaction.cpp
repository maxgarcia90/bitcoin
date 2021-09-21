// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <merkleblock.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/transaction.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>
#include <validationinterface.h>

#include <numeric>
#include <stdint.h>

#include <univalue.h>

static RPCHelpMan sendrawtransaction()
{
    return RPCHelpMan{"sendrawtransaction",
                "\nSubmit a raw transaction (serialized, hex-encoded) to local node and network.\n"
                "\nThe transaction will be sent unconditionally to all peers, so using sendrawtransaction\n"
                "for manual rebroadcast may degrade privacy by leaking the transaction's origin, as\n"
                "nodes will normally not rebroadcast non-wallet transactions already in their mempool.\n"
                "\nA specific exception, RPC_TRANSACTION_ALREADY_IN_CHAIN, may throw if the transaction cannot be added to the mempool.\n"
                "\nRelated RPCs: createrawtransaction, signrawtransactionwithkey\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
                    {"maxfeerate", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())},
                        "Reject transactions whose fee rate is higher than the specified value, expressed in " + CURRENCY_UNIT +
                            "/kvB.\nSet to 0 to accept any fee rate.\n"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The transaction hash in hex"
                },
                RPCExamples{
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {
        UniValue::VSTR,
        UniValueType(), // VNUM or VSTR, checked inside AmountFromValue()
    });

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));

    const CFeeRate max_raw_tx_fee_rate = request.params[1].isNull() ?
                                             DEFAULT_MAX_RAW_TX_FEE_RATE :
                                             CFeeRate(AmountFromValue(request.params[1]));

    int64_t virtual_size = GetVirtualTransactionSize(*tx);
    CAmount max_raw_tx_fee = max_raw_tx_fee_rate.GetFee(virtual_size);

    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, max_raw_tx_fee, /*relay*/ true, /*wait_callback*/ true);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }

    return tx->GetHash().GetHex();
},
    };
}

static RPCHelpMan testmempoolaccept()
{
    return RPCHelpMan{"testmempoolaccept",
                "\nReturns result of mempool acceptance tests indicating if raw transaction(s) (serialized, hex-encoded) would be accepted by mempool.\n"
                "\nIf multiple transactions are passed in, parents must come before children and package policies apply: the transactions cannot conflict with any mempool transactions or each other.\n"
                "\nIf one transaction fails, other transactions may not be fully validated (the 'allowed' key will be blank).\n"
                "\nThe maximum number of transactions allowed is " + ToString(MAX_PACKAGE_COUNT) + ".\n"
                "\nThis checks if transactions violate the consensus or policy rules.\n"
                "\nSee sendrawtransaction call.\n",
                {
                    {"rawtxs", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of hex strings of raw transactions.",
                        {
                            {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                        },
                        },
                    {"maxfeerate", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())},
                     "Reject transactions whose fee rate is higher than the specified value, expressed in " + CURRENCY_UNIT + "/kvB\n"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "The result of the mempool acceptance test for each raw transaction in the input array.\n"
                        "Returns results for each transaction in the same order they were passed in.\n"
                        "Transactions that cannot be fully validated due to failures in other transactions will not contain an 'allowed' result.\n",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction hash in hex"},
                            {RPCResult::Type::STR_HEX, "wtxid", "The transaction witness hash in hex"},
                            {RPCResult::Type::STR, "package-error", "Package validation error, if any (only possible if rawtxs had more than 1 transaction)."},
                            {RPCResult::Type::BOOL, "allowed", "Whether this tx would be accepted to the mempool and pass client-specified maxfeerate."
                                                               "If not present, the tx was not fully validated due to a failure in another tx in the list."},
                            {RPCResult::Type::NUM, "vsize", "Virtual transaction size as defined in BIP 141. This is different from actual serialized size for witness transactions as witness data is discounted (only present when 'allowed' is true)"},
                            {RPCResult::Type::OBJ, "fees", "Transaction fees (only present if 'allowed' is true)",
                            {
                                {RPCResult::Type::STR_AMOUNT, "base", "transaction fee in " + CURRENCY_UNIT},
                            }},
                            {RPCResult::Type::STR, "reject-reason", "Rejection string (only present when 'allowed' is false)"},
                        }},
                    }
                },
                RPCExamples{
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"") +
            "\nTest acceptance of the transaction (signed hex)\n"
            + HelpExampleCli("testmempoolaccept", R"('["signedhex"]')") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("testmempoolaccept", "[\"signedhex\"]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {
        UniValue::VARR,
        UniValueType(), // VNUM or VSTR, checked inside AmountFromValue()
    });
    const UniValue raw_transactions = request.params[0].get_array();
    if (raw_transactions.size() < 1 || raw_transactions.size() > MAX_PACKAGE_COUNT) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Array must contain between 1 and " + ToString(MAX_PACKAGE_COUNT) + " transactions.");
    }

    const CFeeRate max_raw_tx_fee_rate = request.params[1].isNull() ?
                                             DEFAULT_MAX_RAW_TX_FEE_RATE :
                                             CFeeRate(AmountFromValue(request.params[1]));

    std::vector<CTransactionRef> txns;
    txns.reserve(raw_transactions.size());
    for (const auto& rawtx : raw_transactions.getValues()) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, rawtx.get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                               "TX decode failed: " + rawtx.get_str() + " Make sure the tx has at least one input.");
        }
        txns.emplace_back(MakeTransactionRef(std::move(mtx)));
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    CTxMemPool& mempool = EnsureMemPool(node);
    CChainState& chainstate = EnsureChainman(node).ActiveChainstate();
    const PackageMempoolAcceptResult package_result = [&] {
        LOCK(::cs_main);
        if (txns.size() > 1) return ProcessNewPackage(chainstate, mempool, txns, /* test_accept */ true);
        return PackageMempoolAcceptResult(txns[0]->GetWitnessHash(),
               AcceptToMemoryPool(chainstate, mempool, txns[0], /* bypass_limits */ false, /* test_accept*/ true));
    }();

    UniValue rpc_result(UniValue::VARR);
    // We will check transaction fees while we iterate through txns in order. If any transaction fee
    // exceeds maxfeerate, we will leave the rest of the validation results blank, because it
    // doesn't make sense to return a validation result for a transaction if its ancestor(s) would
    // not be submitted.
    bool exit_early{false};
    for (const auto& tx : txns) {
        UniValue result_inner(UniValue::VOBJ);
        result_inner.pushKV("txid", tx->GetHash().GetHex());
        result_inner.pushKV("wtxid", tx->GetWitnessHash().GetHex());
        if (package_result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY) {
            result_inner.pushKV("package-error", package_result.m_state.GetRejectReason());
        }
        auto it = package_result.m_tx_results.find(tx->GetWitnessHash());
        if (exit_early || it == package_result.m_tx_results.end()) {
            // Validation unfinished. Just return the txid and wtxid.
            rpc_result.push_back(result_inner);
            continue;
        }
        const auto& tx_result = it->second;
        if (tx_result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
            const CAmount fee = tx_result.m_base_fees.value();
            // Check that fee does not exceed maximum fee
            const int64_t virtual_size = GetVirtualTransactionSize(*tx);
            const CAmount max_raw_tx_fee = max_raw_tx_fee_rate.GetFee(virtual_size);
            if (max_raw_tx_fee && fee > max_raw_tx_fee) {
                result_inner.pushKV("allowed", false);
                result_inner.pushKV("reject-reason", "max-fee-exceeded");
                exit_early = true;
            } else {
                // Only return the fee and vsize if the transaction would pass ATMP.
                // These can be used to calculate the feerate.
                result_inner.pushKV("allowed", true);
                result_inner.pushKV("vsize", virtual_size);
                UniValue fees(UniValue::VOBJ);
                fees.pushKV("base", ValueFromAmount(fee));
                result_inner.pushKV("fees", fees);
            }
        } else {
            result_inner.pushKV("allowed", false);
            const TxValidationState state = tx_result.m_state;
            if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS) {
                result_inner.pushKV("reject-reason", "missing-inputs");
            } else {
                result_inner.pushKV("reject-reason", state.GetRejectReason());
            }
        }
        rpc_result.push_back(result_inner);
    }
    return rpc_result;
},
    };
}

void RegisterRawTransactionRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category               actor (function)
  //  ---------------------  -----------------------
    { "rawtransactions",     &sendrawtransaction,         },
    { "rawtransactions",     &testmempoolaccept,          },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
