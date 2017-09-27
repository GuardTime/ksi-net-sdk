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
        ///     Policy for verifying KSI signature with user provided publication.
        /// </summary>
        private class UserProvidedPublicationBasedVerificationPolicy : VerificationPolicy
        {
            /// <summary>
            ///     Create user provided publication based verification policy with given rules.
            /// </summary>
            public UserProvidedPublicationBasedVerificationPolicy()
            {
                VerificationRule verificationRule = new UserProvidedPublicationCreationTimeVerificationRule()
                    .OnSuccess(new ExtendingPermittedVerificationRule()
                        .OnSuccess(new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule()
                            .OnSuccess(new UserProvidedPublicationHashMatchesExtendedResponseRule()
                                .OnSuccess(new UserProvidedPublicationHashMatchesExtendedResponseRule()
                                    .OnSuccess(new UserProvidedPublicationTimeMatchesExtendedResponseRule()
                                        .OnSuccess(new UserProvidedPublicationExtendedSignatureInputHashRule()))))));

                FirstRule = new UserProvidedPublicationExistenceRule()
                    .OnSuccess(new SignaturePublicationRecordExistenceRule()
                        .OnSuccess(new UserProvidedPublicationVerificationRule()
                            .OnSuccess(new CalendarHashChainAlgorithmDeprecatedRule()
                                .OnNa(verificationRule))
                            .OnNa(verificationRule))
                        .OnNa(verificationRule));
            }
        }
    }
}