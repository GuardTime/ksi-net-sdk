/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     This rule verifies input hash for aggregation chain. If RFC3161 record is present then document hash is first
    ///     hashed to aggregation input hash and is then compared. Otherwise document hash is compared directly to input hash.
    /// </summary>
    public sealed class AggregationChainInputHashVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            DataHash inputHash = context.DocumentHash;
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(signature, false);
            DataHash aggregationHashChainInputHash = aggregationHashChains[0].InputHash;

            if (signature.IsRfc3161Signature)
            {
                IDataHasher hasher = KsiProvider.GetDataHasher(aggregationHashChainInputHash.Algorithm);

                if (signature.Rfc3161Record == null)
                {
                    throw new KsiVerificationException("No RFC 3161 record in KSI signature.");
                }

                hasher.AddData(signature.Rfc3161Record.GetOutputHash(inputHash).Imprint);
                inputHash = hasher.GetHash();

                return inputHash != aggregationHashChainInputHash
                    ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int01)
                    : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            if (inputHash == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            return inputHash != aggregationHashChainInputHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Gen01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}