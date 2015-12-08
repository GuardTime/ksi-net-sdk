using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that last aggregation hash chain output hash is equal to calendar hash chain input hash. If calendar
    ///     hash chain is missing, status <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainInputHashVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarHashChain calendarHashChain = GetCalendarHashChain(signature, true);

            // If calendar hash chain is missing, verification successful
            if (calendarHashChain == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            return signature.GetAggregationHashChainRootHash() != calendarHashChain.InputHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int03)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}