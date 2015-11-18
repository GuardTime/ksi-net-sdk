using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that publications file publication hash matches with extender reponse calendar hash chain root hash.
    /// </summary>
    public sealed class PublicationsFilePublicationHashMatchesExtenderResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            IPublicationsFile publicationsFile = GetPublicationsFile(context);
            CalendarHashChain signatureCalendarHashChain = GetCalendarHashChain(GetSignature(context));
            PublicationRecord publicationRecord = publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);

            if (publicationRecord == null)
            {
                throw new KsiVerificationException("No publication record found after registration time in publications file: " + signatureCalendarHashChain.RegistrationTime + ".");
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);

            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException("Received invalid extended calendar hash chain from context extension function: null.");
            }

            return extendedTimeCalendarHashChain.OutputHash != publicationRecord.PublicationData.PublicationHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}