using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Signature publication record publication hash verification VerificationRule.
    /// </summary>
    public sealed class SignaturePublicationRecordPublicationTimeRule : VerificationRule
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

            if (context.Signature.PublicationRecord == null)
            {
                return VerificationResult.Ok;
            }

            PublicationData publicationRecordPublicationData = context.Signature.PublicationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = context.Signature.CalendarHashChain.PublicationData;

            if (publicationRecordPublicationData.PublicationTime != calendarHashChainPublicationData.PublicationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}