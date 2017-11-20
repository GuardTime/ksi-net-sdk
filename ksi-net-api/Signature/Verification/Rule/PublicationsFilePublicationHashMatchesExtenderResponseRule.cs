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

using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that publications file publication hash matches with extender reponse calendar hash chain root hash.
    /// </summary>
    public sealed class PublicationsFilePublicationHashMatchesExtenderResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IPublicationsFile publicationsFile = GetPublicationsFile(context);
            IKsiSignature signature = GetSignature(context);

            PublicationRecordInPublicationFile publicationRecord = GetNearestPublicationRecord(publicationsFile, signature.AggregationTime, true);

            if (publicationRecord == null)
            {
                // if suitable publication record does not exist in publications file then return NA
                return new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
            }

            CalendarHashChain extendedCalendarHashChain = GetExtendedCalendarHashChain(context, publicationRecord.PublicationData.PublicationTime);

            return extendedCalendarHashChain.OutputHash != publicationRecord.PublicationData.PublicationHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}