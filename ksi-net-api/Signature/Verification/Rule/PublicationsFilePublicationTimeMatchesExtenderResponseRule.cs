using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class PublicationsFilePublicationTimeMatchesExtenderResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            PublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                // TODO: better exception
                throw new InvalidOperationException("Invalid publication provided by user: null");
            }

            CalendarHashChain signatureCalendarHashChain = context.Signature.CalendarHashChain;
            if (signatureCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid signature calendar hash chain: null");
            }

            PublicationRecord publicationRecord = publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);
            if (publicationRecord == null)
            {
                throw new InvalidOperationException("No publication record found after registration time: " + signatureCalendarHashChain.RegistrationTime);
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid extended calendar hash chain: null");
            }

            if (context.Signature.GetAggregationHashChainRootHash() != extendedTimeCalendarHashChain.InputHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}