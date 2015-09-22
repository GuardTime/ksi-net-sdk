using Guardtime.KSI.Hashing;
using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Aggregation hash chain input hash verification VerificationRule.
    /// </summary>
    public sealed class AggregationChainInputHashVerificationRule : VerificationRule
    {

        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
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
