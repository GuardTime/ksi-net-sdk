using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class UserProvidedPublicationTimeMatchesExtendedResponseRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                // TODO: better exception
                throw new InvalidOperationException("Invalid publication provided by user: null");
            }

            // s
            KsiSignature signature = context.Signature;
            if (signature == null)
            {
                throw new InvalidOperationException("Invalid signature provided by user: null");
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);

            if (userPublication.PublicationTime != extendedTimeCalendarHashChain.PublicationData.PublicationTime)
            {
                return VerificationResult.Fail;
            }
            // calculate round time and check that it matches with aggregation hash chain aggregation time
            if (signature.AggregationTime != extendedTimeCalendarHashChain.RegistrationTime)
            {
                return VerificationResult.Fail;
            }


            return VerificationResult.Ok;
        }
    }
}