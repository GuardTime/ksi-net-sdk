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
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            CalendarHashChain extendedCalendarHashChain = calendarHashChain == null
                ? context.GetExtendedLatestCalendarHashChain()
                : context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Received invalid extended calendar hash chain from context extension function: null.");
            }

            if (context.Signature.GetAggregationHashChainRootHash() != extendedCalendarHashChain.InputHash)
            {
                // TODO: Log
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Cal02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}