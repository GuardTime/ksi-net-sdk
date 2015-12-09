using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if extended signature aggregation hash chain links are with same structure and right links are equal to
    ///     not extended signature right links.
    /// </summary>
    public sealed class ExtendedSignatureAggregationChainRightLinksMatchesRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            ulong publicationTime = GetCalendarHashChain(signature).PublicationData.PublicationTime;
            CalendarHashChain extendedCalendarHashChain = GetExtendedTimeCalendarHashChain(context, publicationTime);

            return !GetCalendarHashChain(signature).AreRightLinksEqual(extendedCalendarHashChain)
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Cal04)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}