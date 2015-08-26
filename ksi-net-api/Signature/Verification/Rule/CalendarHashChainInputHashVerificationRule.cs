using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class CalendarHashChainInputHashVerificationRule : IRule
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

            DataHash aggregationHashChainRootHash = context.GetAggregationHashChainRootHash();
            if (aggregationHashChainRootHash == null)
            {
                return VerificationResult.FAIL;
            }

            if (aggregationHashChainRootHash != calendarHashChain.InputHash)
            {
                return VerificationResult.FAIL;
            }
          
            return VerificationResult.OK;
        }
    }
}
