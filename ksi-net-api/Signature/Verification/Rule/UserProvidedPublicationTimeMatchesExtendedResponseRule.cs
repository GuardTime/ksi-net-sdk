using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationTimeMatchesExtendedResponseRule : VerificationRule
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

            PublicationData userPublication = context.UserPublication;
            if (userPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null");
            }

            IKsiSignature signature = context.Signature;
            if (signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null");
            }

            CalendarHashChain extendedTimeCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(userPublication.PublicationTime);

            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null");
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