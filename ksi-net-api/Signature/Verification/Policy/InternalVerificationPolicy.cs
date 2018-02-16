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

using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Policy for verifying KSI signature internal consistency.
    /// </summary>
    public class InternalVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create internal verification policy.
        /// </summary>
        public InternalVerificationPolicy()
        {
            FirstRule = GetInputVerificationRules(
                GetRfc3161Rules(
                    GetAggregationChainRules(
                        // Verify calendar hash chain if exists
                        new CalendarHashChainExistenceRule() // Gen-02
                            .OnSuccess(GetCalendarChainRules(
                                // Verify calendar auth record if exists
                                new CalendarAuthenticationRecordExistenceRule() // Gen-02
                                    .OnSuccess(CalendarAuthRecordRules)
                                    // No calendar auth record. Verify publication record.
                                    .OnNa(PublicationRules)))
                            // No calendar hash chain
                            .OnNa(new OkResultRule()))));
        }

        private static VerificationRule GetInputVerificationRules(VerificationRule innerSuccessRules)
        {
            return new InputHashAlgorithmVerificationRule() // Gen-04
                .OnSuccess(new DocumentHashVerificationRule() // Gen-01
                    .OnSuccess(new DocumentHashLevelVerificationRule() // Gen-03
                        .OnSuccess(new InputHashAlgorithmDeprecatedRule() // Int-13
                            .OnSuccess(innerSuccessRules))));
        }

        private static VerificationRule GetRfc3161Rules(VerificationRule innerSuccessRules)
        {
            return new Rfc3161RecordHashAlgorithmDeprecatedRule() // Int-14
                .OnSuccess(new Rfc3161RecordOutputHashAlgorithmDeprecatedRule() // Int-17
                    .OnSuccess(new Rfc3161RecordChainIndexRule() // Int-12
                        .OnSuccess(new Rfc3161RecordOutputHashVerificationRule() // Int-01
                            .OnSuccess(new Rfc3161RecordAggregationTimeRule() // Int-02
                                .OnSuccess(innerSuccessRules)))));
        }

        private static VerificationRule GetAggregationChainRules(VerificationRule innerSuccessRules)
        {
            return new AggregationHashChainIndexSuccessorRule() // Int-12
                .OnSuccess(new AggregationHashChainMetadataRule() // Int-11
                    .OnSuccess(new AggregationHashChainAlgorithmDeprecatedRule() // Int-15
                        .OnSuccess(new AggregationHashChainConsistencyRule() // Int-01
                            .OnSuccess(new AggregationHashChainTimeConsistencyRule() // Int-02
                                .OnSuccess(new AggregationHashChainShapeRule() // Int-10
                                    .OnSuccess(innerSuccessRules))))));
        }

        private static VerificationRule GetCalendarChainRules(VerificationRule innerSuccessRules)
        {
            return new CalendarHashChainInputHashVerificationRule() // Int-03
                .OnSuccess(new CalendarHashChainAggregationTimeRule() // Int-04
                    .OnSuccess(new CalendarHashChainRegistrationTimeRule() // Int-05
                        .OnSuccess(new CalendarHashChainAlgorithmObsoleteRule() // Int-16
                            .OnSuccess(innerSuccessRules))));
        }

        private static VerificationRule CalendarAuthRecordRules =>
            new CalendarAuthenticationRecordPublicationTimeRule() // Int-06
                .OnSuccess(new CalendarAuthenticationRecordAggregationHashRule()); // Int-08

        private static VerificationRule PublicationRules =>
            new SignaturePublicationRecordExistenceRule() // Gen-02
                .OnSuccess(new SignaturePublicationRecordPublicationTimeRule() // Int-07
                    .OnSuccess(new SignaturePublicationRecordPublicationHashRule())) // Int-09
                // No publication record
                .OnNa(new OkResultRule());
    }
}