using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class CalendarAuthenticationRecordAggregationHashRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            KsiSignature signature = context.Signature;
            if (signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                return VerificationResult.Ok;
            }

            CalendarHashChain calendarHashChain = signature.CalendarHashChain;
            if (calendarHashChain.OutputHash != calendarAuthenticationRecord.PublicationData.PublicationHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}