using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication hash matches extender response calendar hash chain root hash.
    /// </summary>
    public sealed class UserProvidedPublicationHashMatchesExtendedResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            PublicationData userPublication = GetUserPublication(context);
            CalendarHashChain extendedCalendarHashChain = GetExtendedTimeCalendarHashChain(context, userPublication.PublicationTime);



            return extendedCalendarHashChain.PublicationData.PublicationHash != userPublication.PublicationHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}