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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verifies that extender response calendar hash chain right link hash algorithms are not deprecated.
    /// </summary>
    public sealed class ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            PublicationData publicationData;

            if (context.UserPublication != null)
            {
                publicationData = context.UserPublication;
            }
            else
            {
                PublicationRecordInPublicationFile publicationRecord = GetNearestPublicationRecord(GetPublicationsFile(context), signature.AggregationTime, true);

                if (publicationRecord == null)
                {
                    // if suitable publication record does not exist in publications file then return NA
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
                }

                publicationData = publicationRecord.PublicationData;
            }

            CalendarHashChain extendedCalendarHashChain = GetExtendedCalendarHashChain(context, publicationData.PublicationTime);
            HashAlgorithm deprecatedHashAlgorithm = GetDeprecatedHashAlgorithm(extendedCalendarHashChain);

            if (deprecatedHashAlgorithm != null)
            {
                Logger.Debug("Extender response calendar hash chain contains deprecated aggregation algorithm at publication time. Algorithm: {0}; Publication time: {1}",
                    deprecatedHashAlgorithm.Name, extendedCalendarHashChain.PublicationTime);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}