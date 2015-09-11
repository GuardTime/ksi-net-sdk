using Guardtime.KSI.Hashing;
using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Aggregation hash chain input hash verification rule.
    /// </summary>
    public sealed class AggregationChainInputHashVerificationRule : IRule
    {

        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(VerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            KsiSignature signature = context.Signature;
            DataHash inputHash = context.DocumentHash;
            if (signature == null)
            {
                throw new ArgumentException("Invalid signature in context: null", "context");
            }

            if (signature.IsRfc3161Signature)
            {
                inputHash = signature.Rfc3161Record.GetOutputHash(inputHash);
            }

            return inputHash != signature.GetAggregationHashChains()[0].InputHash ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}
