using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extender response calendar hash chain (extension request with current calendar hash chain
    ///     aggregation and publication time is used) matches with current calendar hash chain root hash. If current signature
    ///     does not contain calendar hash chain, <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class ExtendedSignatureCalendarChainRootHashRule : VerificationRule
    {
        public const string RuleName = "ExtendedSignatureCalendarChainRootHashRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            if (context.Signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publications record in KSI signature: null.");
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in KSI signature: null.");
            }

            CalendarHashChain extendedSignatureCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationTime);
            if (extendedSignatureCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null.");
            }

            return calendarHashChain.OutputHash != extendedSignatureCalendarHashChain.OutputHash
                ? new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Cal01)
                : new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}