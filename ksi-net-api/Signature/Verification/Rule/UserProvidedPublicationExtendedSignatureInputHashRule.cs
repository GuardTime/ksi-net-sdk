using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationExtendedSignatureInputHashRule : VerificationRule
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

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null");
            }

            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null");
            }

            CalendarHashChain extendedTimeCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null");
            }

            if (extendedTimeCalendarHashChain.InputHash != context.Signature.GetAggregationHashChainRootHash())
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}