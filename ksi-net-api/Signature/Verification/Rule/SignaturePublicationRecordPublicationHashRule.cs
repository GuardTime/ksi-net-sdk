using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if KSI signature contains publication record. If publication record is missing,
    ///     <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class SignaturePublicationRecordPublicationHashRule : VerificationRule
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

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            PublicationRecord publicationRecord = context.Signature.PublicationRecord;
            if (publicationRecord == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain is missing in KSI signature.");
            }

            return publicationRecord.PublicationData.PublicationHash !=
                   calendarHashChain.PublicationData.PublicationHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int09)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}