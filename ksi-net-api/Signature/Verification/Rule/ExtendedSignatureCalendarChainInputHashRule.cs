using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extended signature contains correct calendar hash chain input hash. It means that input hash
    ///     equals to aggregation hash chain root hash.
    /// </summary>
    public sealed class ExtendedSignatureCalendarChainInputHashRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarHashChain calendarHashChain = GetCalendarHashChain(signature, true);
            CalendarHashChain extendedCalendarHashChain = calendarHashChain == null
                ? context.GetExtendedLatestCalendarHashChain()
                : context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException("Received invalid extended calendar hash chain from context extension function: null.");
            }

            return signature.GetAggregationHashChainRootHash() != extendedCalendarHashChain.InputHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Cal02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}