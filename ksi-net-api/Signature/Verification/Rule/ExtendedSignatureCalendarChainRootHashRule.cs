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
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarHashChain calendarHashChain = GetCalendarHashChain(GetSignature(context));
            CalendarHashChain extendedSignatureCalendarHashChain = GetExtendedTimeCalendarHashChain(context, calendarHashChain.PublicationTime);

            return calendarHashChain.OutputHash != extendedSignatureCalendarHashChain.OutputHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Cal01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}