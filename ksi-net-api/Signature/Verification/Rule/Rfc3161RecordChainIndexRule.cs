/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     This rule verifies that aggregation hash chain index and RFC3161 record chain index match.
    ///     If RFC3161 record is not present then <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class Rfc3161RecordChainIndexRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (signature.IsRfc3161Signature)
            {
                ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(signature, false);

                ulong[] rfc3161ChainIndex = signature.Rfc3161Record.GetChainIndex();
                ulong[] aggregationChainIndex = aggregationHashChains[0].GetChainIndex();

                if (rfc3161ChainIndex.Length != aggregationChainIndex.Length)
                {
                    Logger.Debug(
                        string.Format("Aggregation hash chain index and RFC3161 chain index mismatch. Aggregation chain index length is {0} and RFC3161 chain index length is {1}",
                            aggregationChainIndex.Length, rfc3161ChainIndex.Length));

                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int12);
                }

                for (int i = 0; i < rfc3161ChainIndex.Length; i++)
                {
                    ulong rfc3161Index = rfc3161ChainIndex[i];
                    ulong aggregationIndex = aggregationChainIndex[i];

                    if (!rfc3161Index.Equals(aggregationIndex))
                    {
                        Logger.Debug(string.Format(
                            "Aggregation hash chain index and RFC3161 chain index mismatch. At position {0} aggregation chain index value is {1} and RFC3161 chain index value is {2}",
                            i, aggregationIndex, rfc3161Index));
                        return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int12);
                    }
                }
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}