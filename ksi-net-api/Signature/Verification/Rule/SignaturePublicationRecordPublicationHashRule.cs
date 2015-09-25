using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class SignaturePublicationRecordPublicationHashRule : VerificationRule
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

            PublicationRecord publicationRecord = context.Signature.PublicationRecord;
            if (publicationRecord == null)
            {
                return VerificationResult.Ok;
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain missing in KSI signature");
            }

            return publicationRecord.PublicationData.PublicationHash !=
                   calendarHashChain.PublicationData.PublicationHash
                ? VerificationResult.Fail
                : VerificationResult.Ok;
        }
    }
}