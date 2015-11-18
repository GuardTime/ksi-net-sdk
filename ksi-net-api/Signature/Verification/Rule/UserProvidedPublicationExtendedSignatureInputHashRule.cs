using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extender response input hash equals to signature aggregation root hash.
    /// </summary>
    public sealed class UserProvidedPublicationExtendedSignatureInputHashRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(GetUserPublication(context).PublicationTime);

            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException("Received invalid extended calendar hash chain from context extension function: null.");
            }

            return extendedTimeCalendarHashChain.InputHash != GetSignature(context).GetAggregationHashChainRootHash()
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub03)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}