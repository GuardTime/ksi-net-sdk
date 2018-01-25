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

using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Policy for verifying KSI signature with calendar.
    /// </summary>
    public class CalendarBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create calendar based verification policy with given rules.
        /// </summary>
        public CalendarBasedVerificationPolicy()
        {
            VerificationRule verificationRule = new ExtendedSignatureCalendarChainInputHashRule() // Cal-02
                .OnSuccess(new ExtendedSignatureCalendarChainAggregationTimeRule()); // Cal-03

            FirstRule = new InternalVerificationPolicy()
                .OnSuccess(new CalendarHashChainExistenceRule() // // Gen-02
                    .OnSuccess(new SignaturePublicationRecordExistenceRule() // Gen-02
                        .OnSuccess(new ExtendedSignatureCalendarChainRootHashRule() // Cal-01
                            .OnSuccess(verificationRule))
                        .OnNa(new ExtendedSignatureCalendarHashChainRightLinksMatchRule() // Cal-4
                            .OnSuccess(verificationRule)))
                    .OnNa(verificationRule));
        }
    }
}