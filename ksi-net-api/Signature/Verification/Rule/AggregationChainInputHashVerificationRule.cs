using Guardtime.KSI.Hashing;
using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Aggregation hash chain input hash verification rule.
    /// </summary>
    public class AggregationChainInputHashVerificationRule : IRule
    {
        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(VerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            KsiSignature signature = context.Signature;
            DataHash inputHash = context.DocumentHash, documentHash = context.DocumentHash;
            if (signature == null)
            {
                throw new ArgumentException("Invalid signature in context: null", "context");
            }

            if (signature.IsRfc3161Signature)
            {
                inputHash = signature.Rfc3161Record.GetOutputHash(documentHash);
            }

            if (inputHash != signature.GetAggregationHashChains()[0].InputHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}
