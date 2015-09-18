using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class PublicationsFileExtendedSignatureInputHashRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                // TODO: better exception
                throw new InvalidOperationException("Invalid publication provided by user: null");
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);

            if (extendedTimeCalendarHashChain.InputHash != context.GetAggregationHashChainRootHash())
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}