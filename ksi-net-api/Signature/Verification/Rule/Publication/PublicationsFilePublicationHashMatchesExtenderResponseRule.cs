using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class PublicationsFilePublicationHashMatchesExtenderResponseRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            PublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                // TODO: better exception
                throw new InvalidOperationException("Invalid publication provided by user: null");
            }

            CalendarHashChain signatureCalendarHashChain = context.CalendarHashChain;
            if (signatureCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid signature calendar hash chain: null");
            }

            PublicationRecord publicationRecord = publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);
            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);

            if (extendedTimeCalendarHashChain.PublicationData.PublicationHash != publicationRecord.PublicationData.PublicationHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}