using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication time matches extender response calendar hash chain registration time.
    /// </summary>
    public sealed class UserProvidedPublicationTimeMatchesExtendedResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null.");
            }

            IKsiSignature signature = context.Signature;
            if (signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            CalendarHashChain extendedTimeCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);

            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Received invalid extended calendar hash chain from context extension function: null.");
            }

            if (userPublication.PublicationTime != extendedTimeCalendarHashChain.PublicationData.PublicationTime)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub02);
            }

            if (signature.AggregationTime != extendedTimeCalendarHashChain.RegistrationTime)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub02);
            }


            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}