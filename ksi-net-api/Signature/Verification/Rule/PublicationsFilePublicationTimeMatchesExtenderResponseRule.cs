using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class PublicationsFilePublicationTimeMatchesExtenderResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
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

            PublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null");
            }

            CalendarHashChain signatureCalendarHashChain = context.Signature.CalendarHashChain;
            if (signatureCalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in signature: null");
            }

            PublicationRecord publicationRecord = publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);
            if (publicationRecord == null)
            {
                throw new KsiVerificationException("No publication record found in publications file after registration time: " + signatureCalendarHashChain.RegistrationTime);
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid extended calendar hash chain from context extension function: null");
            }

            if (publicationRecord.PublicationData.PublicationTime != extendedTimeCalendarHashChain.PublicationTime)
            {
                return VerificationResult.Fail;
            }

            if (context.Signature.AggregationTime != extendedTimeCalendarHashChain.RegistrationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}