using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Rule verifies that calendar authentication record aggregation time equals to calendar hash chain aggregation time. Without calendar authentication record <see cref="VerificationResult.Ok"/> is returned.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationTimeRule : VerificationRule
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

            KsiSignature signature = context.Signature;
            if (signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature: null");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                return VerificationResult.Ok;
            }

            CalendarHashChain calendarHashChain = signature.CalendarHashChain;
            if (calendarHashChain.PublicationTime != calendarAuthenticationRecord.PublicationData.PublicationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}