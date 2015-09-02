using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    internal class SignaturePublicationRecordPublicationTimeRule : IRule
    {
        public VerificationResult Verify(VerificationContext context)
        {
            if (context.PublicationRecord == null)
            {
                return VerificationResult.Ok;
            }

            // TODO: Check!
            PublicationRecord publicationRecord = context.PublicationRecord;
            CalendarHashChain calendarHashChain = context.CalendarHashChain;

            if (publicationRecord.PublicationData.PublicationHash.Value != calendarHashChain.PublicationData.PublicationHash.Value)
            {
                return VerificationResult.Fail;
            }
            return VerificationResult.Ok;
        }
    }
}