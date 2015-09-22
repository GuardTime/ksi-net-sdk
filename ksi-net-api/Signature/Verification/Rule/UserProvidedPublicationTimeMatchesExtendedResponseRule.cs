using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationTimeMatchesExtendedResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                // TODO: better exception
                throw new InvalidOperationException("Invalid publication provided by user: null");
            }

            KsiSignature signature = context.Signature;
            if (signature == null)
            {
                throw new InvalidOperationException("Invalid signature provided by user: null");
            }

            CalendarHashChain extendedTimeCalendarHashChain = context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);

            if (extendedTimeCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid extended calendar hash chain: null");
            }

            if (userPublication.PublicationTime != extendedTimeCalendarHashChain.PublicationData.PublicationTime)
            {
                return VerificationResult.Fail;
            }

            if (signature.AggregationTime != extendedTimeCalendarHashChain.RegistrationTime)
            {
                return VerificationResult.Fail;
            }


            return VerificationResult.Ok;
        }
    }
}