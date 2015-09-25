using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class PublicationsFilePublicationHashMatchesExtenderResponseRule : VerificationRule
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
                throw new KsiVerificationException("Invalid KSI signature in context: null");
            }

            IPublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publication provided by user: null");
            }

            CalendarHashChain signatureCalendarHashChain = context.Signature.CalendarHashChain;
            if (signatureCalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in signature: null");
            }

            PublicationRecord publicationRecord =
                publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);
            if (publicationRecord == null)
            {
                throw new KsiVerificationException(
                    "No publication record found after registration time in publications file: " +
                    signatureCalendarHashChain.RegistrationTime);
            }

            CalendarHashChain extendedTimeCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null");
            }

            if (extendedTimeCalendarHashChain.OutputHash != publicationRecord.PublicationData.PublicationHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}