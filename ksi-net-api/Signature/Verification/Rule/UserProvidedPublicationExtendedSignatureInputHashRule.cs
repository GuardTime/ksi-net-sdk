using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationExtendedSignatureInputHashRule : VerificationRule
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

            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                throw new InvalidOperationException("Invalid publication provided by user: null");
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid extended calendar hash chain: null");
            }

            if (extendedTimeCalendarHashChain.InputHash != context.Signature.GetAggregationHashChainRootHash())
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}