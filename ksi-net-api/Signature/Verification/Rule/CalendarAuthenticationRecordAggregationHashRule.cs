using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that calendar authentication record publication hash equals to calendar hash chain publication hash.
    ///     Without calendar authentication record <see cref="VerificationResult.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationHashRule : VerificationRule
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

            IKsiSignature signature = context.Signature;
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
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain missing from KSI signature");
            }

            if (calendarHashChain.OutputHash != calendarAuthenticationRecord.PublicationData.PublicationHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}