using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extender response input hash equals to signature aggregation root hash.
    /// </summary>
    public sealed class UserProvidedPublicationExtendedSignatureInputHashRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        
        
        public override VerificationResult Verify(IVerificationContext context)
        {
            ulong publicationTime = GetUserPublication(context).PublicationTime;
            CalendarHashChain extendedTimeCalendarHashChain = GetExtendedTimeCalendarHashChain(context, publicationTime);

            return extendedTimeCalendarHashChain.InputHash != GetSignature(context).GetAggregationHashChainRootHash()
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub03)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}