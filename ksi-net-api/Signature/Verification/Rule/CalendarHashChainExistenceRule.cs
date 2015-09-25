using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule for checking if KSI signature contains calendar hash chain.
    ///     Used for key-based and publication-based verification policies.
    /// </summary>
    public sealed class CalendarHashChainExistenceRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="ArgumentNullException">thrown if context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature: null");
            }

            return context.Signature.CalendarHashChain == null ? VerificationResult.Na : VerificationResult.Ok;
        }
    }
}