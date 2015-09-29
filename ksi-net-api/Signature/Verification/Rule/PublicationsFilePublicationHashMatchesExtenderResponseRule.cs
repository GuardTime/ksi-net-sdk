using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that publications file publication hash matches with extender reponse calendar hash chain root hash.
    /// </summary>
    public sealed class PublicationsFilePublicationHashMatchesExtenderResponseRule : VerificationRule
    {
        public const string RuleName = "PublicationsFilePublicationHashMatchesExtenderResponseRule";

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

            IPublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publication provided by user: null.");
            }

            CalendarHashChain signatureCalendarHashChain = context.Signature.CalendarHashChain;
            if (signatureCalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in KSI signature: null.");
            }

            PublicationRecord publicationRecord =
                publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);
            if (publicationRecord == null)
            {
                throw new KsiVerificationException(
                    "No publication record found after registration time in publications file: " +
                    signatureCalendarHashChain.RegistrationTime + ".");
            }

            CalendarHashChain extendedTimeCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Received invalid extended calendar hash chain from context extension function: null.");
            }

            if (extendedTimeCalendarHashChain.OutputHash != publicationRecord.PublicationData.PublicationHash)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Pub01);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}