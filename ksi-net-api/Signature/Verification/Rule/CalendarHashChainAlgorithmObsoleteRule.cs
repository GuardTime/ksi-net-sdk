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

using System.Collections.Generic;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verifies that calendar hash chain right link hash algorithms were not obsolete at the publication time.
    ///     If calendar hash chain is missing then status <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainAlgorithmObsoleteRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarHashChain calendarHashChain = GetSignature(context).CalendarHashChain;

            // If calendar hash chain is missing, verification successful
            if (calendarHashChain == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            IEnumerator<CalendarHashChain.Link> linksEnumerator = calendarHashChain.GetLeftLinksEnumerator();
            CalendarHashChain.Link link = linksEnumerator.MoveNext() ? linksEnumerator.Current : null;

            while (link != null)
            {
                if (link.Value.Algorithm.IsObsolete(calendarHashChain.PublicationTime))
                {
                    Logger.Debug("Calendar hash chain contains obsolete aggregation algorithm at publication time. Algorithm: {0}; Publication time: {1}",
                        link.Value.Algorithm.Name, calendarHashChain.PublicationTime);
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int16);
                }

                link = linksEnumerator.MoveNext() ? linksEnumerator.Current : null;
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}