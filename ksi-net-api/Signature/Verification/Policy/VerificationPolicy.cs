/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using NLog;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Verification policy to verify set of verification rules.
    /// </summary>
    public abstract class VerificationPolicy : VerificationRule
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        ///     First rule to verify.
        /// </summary>
        protected VerificationRule FirstRule;

        /// <summary>
        ///     Verify given context with verification policy.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid context: null.");
            }

            VerificationRule verificationRule = FirstRule;
            List<VerificationResult> verificationResults = new List<VerificationResult>();

            VerificationResult verificationResult;

            try
            {
                while (verificationRule != null)
                {
                    VerificationResult result = verificationRule.Verify(context);
                    verificationResults.Add(result);
                    verificationRule = verificationRule.NextRule(result.ResultCode);
                }
            }
            catch (Exception e)
            {
                Logger.Warn("Error occured on rule {0}: {1}", verificationRule?.GetRuleName(), e);
                verificationResults.Add(new VerificationResult(verificationRule?.GetRuleName(), VerificationResultCode.Na));
                throw;
            }
            finally
            {
                verificationResult = new VerificationResult(GetRuleName(), verificationResults);
                Logger.Debug("{0}{1}{2}", GetRuleName(), Environment.NewLine, verificationResult);
            }

            return verificationResult;
        }
    }
}