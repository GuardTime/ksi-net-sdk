﻿/*
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

using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Policy for verifying KSI signature with PKI.
    /// </summary>
    public class KeyBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create key based verification policy.
        /// </summary>
        [Obsolete("Use KeyBasedVerificationPolicy() instead.")]
        public KeyBasedVerificationPolicy(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector) : this()
        {
        }

        internal KeyBasedVerificationPolicy(bool excludeInternalPolicy)
        {
            FirstRule = excludeInternalPolicy ? GetRules() : new InternalVerificationPolicy().OnSuccess(GetRules());
        }

        /// <summary>
        ///     Create key based verification policy.
        /// </summary>
        public KeyBasedVerificationPolicy()
        {
            FirstRule = new InternalVerificationPolicy()
                .OnSuccess(GetRules());
        }

        private static VerificationRule GetRules()
        {
            return new CalendarHashChainExistenceRule() // Gen-02
                .OnSuccess(new CalendarHashChainAlgorithmDeprecatedRule() // Gen-02
                    .OnSuccess(new CalendarAuthenticationRecordExistenceRule() // Gen-02
                        .OnSuccess(new CertificateExistenceRule() // Key-01
                            .OnSuccess(new CalendarAuthenticationRecordSignatureVerificationRule())))); // Key-02, Key-03
        }
    }
}