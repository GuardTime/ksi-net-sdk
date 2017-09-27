﻿/*
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
    public partial class PublicationBasedVerificationPolicy
    {
        /// <summary>
        ///     Policy for verifying KSI signature with publications file.
        /// </summary>
        private class PublicationsFileVerificationPolicy : VerificationPolicy
        {
            /// <summary>
            ///     Create publications file verification policy instance.
            /// </summary>
            public PublicationsFileVerificationPolicy()
            {
                VerificationRule verificationRule = new ExtendingPermittedVerificationRule()
                    .OnSuccess(new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule()
                        .OnSuccess(new PublicationsFilePublicationHashMatchesExtenderResponseRule() // pub-01
                            .OnSuccess(new PublicationsFilePublicationTimeMatchesExtenderResponseRule() // pub-02
                                .OnSuccess(new PublicationsFileExtendedSignatureInputHashRule())))); // pub-03

                FirstRule = new SignaturePublicationRecordExistenceRule()
                    .OnSuccess(new PublicationsFileSignaturePublicationMatchRule() // pub-05
                        .OnSuccess(new CalendarHashChainAlgorithmDeprecatedRule())
                        .OnNa(verificationRule))
                    .OnNa(verificationRule);
            }
        }
    }
}