using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class SignaturePublicationRecordPublicationTimeRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            if (context.PublicationRecord == null)
            {
                return VerificationResult.Ok;
            }

            // TODO: Check!
            PublicationRecord publicationRecord = context.PublicationRecord;
            CalendarHashChain calendarHashChain = context.CalendarHashChain;

            return publicationRecord.PublicationData.PublicationHash.Value != calendarHashChain.PublicationData.PublicationHash.Value ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}