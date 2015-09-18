using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Signature publication record publication hash verification rule.
    /// </summary>
    public sealed class SignaturePublicationRecordPublicationHashRule : IRule
    {

        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(VerificationContext context)
        {
            if (context.PublicationRecord == null)
            {
                return VerificationResult.Ok;
            }

            // TODO: Check!
            PublicationData publicationRecordPublicationData = context.PublicationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = context.CalendarHashChain.PublicationData;

            if (publicationRecordPublicationData.PublicationTime != calendarHashChainPublicationData.PublicationTime)
            {
                return VerificationResult.Fail;
            }
            return VerificationResult.Ok;
        }
    }
}