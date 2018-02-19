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

using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Verification policy to verify set of verification rules.
    /// </summary>
    public abstract class VerificationPolicy : VerificationRule
    {
        /// <summary>
        ///     First rule to verify.
        /// </summary>
        protected VerificationRule FirstRule;

        /// <summary>
        /// Verify KSI signature with given context and policy.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            return DoVerification(context);
        }

        private VerificationResult DoVerification(IVerificationContext context, bool writeLog = true)
        {
            VerificationRule verificationRule = FirstRule;
            List<VerificationResult> verificationResults = new List<VerificationResult>();

            try
            {
                while (verificationRule != null)
                {
                    VerificationPolicy policy = verificationRule as VerificationPolicy;
                    VerificationResult result = policy != null ? policy.DoVerification(context, false) : verificationRule.Verify(context);
                    verificationResults.Add(result);
                    verificationRule = verificationRule.NextRule(result.ResultCode);
                }
            }
            catch (Exception e)
            {
                KsiVerificationException ksiVerificationException = e as KsiVerificationException;
                VerificationResult resultFromException = ksiVerificationException?.VerificationResult;

                // if inner policy has thrown an exception and verification result is set within the exception then add this result to result list. 
                // otherwise add a new result.
                verificationResults.Add(resultFromException ?? new VerificationResult(verificationRule?.GetRuleName(), VerificationResultCode.Na));
                VerificationResult result = new VerificationResult(GetRuleName(), verificationResults);

                // write log only when topmost policy
                if (writeLog)
                {
                    Logger.Warn("Error occured on rule {0}: {1}{2}{3}", verificationRule?.GetRuleName(), e, Environment.NewLine, result);
                    throw;
                }

                if (resultFromException != null)
                {
                    ksiVerificationException.VerificationResult = result;
                    throw ksiVerificationException;
                }

                throw new KsiVerificationException(e.Message, e) { VerificationResult = result };
            }

            VerificationResult verificationResult = new VerificationResult(GetRuleName(), verificationResults);

            // write log only when topmost policy
            if (writeLog)
            {
                Logger.Debug(Environment.NewLine + verificationResult);
            }

            return verificationResult;
        }
    }
}