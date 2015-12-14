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