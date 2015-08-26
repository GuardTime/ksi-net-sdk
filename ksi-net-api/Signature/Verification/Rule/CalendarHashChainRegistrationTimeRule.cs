using Guardtime.KSI.Hashing;
using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class CalendarHashChainRegistrationTimeRule : IRule
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public VerificationResult Verify(VerificationContext context)
        {

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.OK;
            }

            if (calendarHashChain.AggregationTime != calendarHashChain.RegistrationTime)
            {
                return VerificationResult.FAIL;
            }

            return VerificationResult.OK;
        }
    }
}
