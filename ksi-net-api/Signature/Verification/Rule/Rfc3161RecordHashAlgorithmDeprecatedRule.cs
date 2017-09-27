/*
 * Copyright 2013-2017 Guardtime, Inc.
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

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verifies that all hash algorithms used internally in RFC3161 record were not deprecated at the aggregation time.
    ///     If RFC3161 record is not present then <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class Rfc3161RecordHashAlgorithmDeprecatedRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (signature.IsRfc3161Signature)
            {
                if (signature.Rfc3161Record.SignedAttributesAlgorithm != null &&
                    signature.Rfc3161Record.SignedAttributesAlgorithm.IsDeprecated(signature.Rfc3161Record.AggregationTime))
                {
                    Logger.Debug("Hash algorithm used to hash the SignedAttributes structure was deprecated at aggregation time. Algorithm: {0}; Aggregation time: {1}",
                        signature.Rfc3161Record.SignedAttributesAlgorithm.Name, signature.Rfc3161Record.AggregationTime);
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int14);
                }

                if (signature.Rfc3161Record.TstInfoAlgorithm != null && signature.Rfc3161Record.TstInfoAlgorithm.IsDeprecated(signature.Rfc3161Record.AggregationTime))
                {
                    Logger.Debug("Hash algorithm used to hash the TSTInfo structure was deprecated at aggregation time. Algorithm: {0}; Aggregation time: {1}",
                        signature.Rfc3161Record.TstInfoAlgorithm.Name, signature.Rfc3161Record.AggregationTime);
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int14);
                }
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}