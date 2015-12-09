using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication time matches extender response calendar hash chain registration time.
    /// </summary>
    public sealed class UserProvidedPublicationTimeMatchesExtendedResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            PublicationData userPublication = GetUserPublication(context);
            CalendarHashChain extendedTimeCalendarHashChain = GetExtendedTimeCalendarHashChain(context, userPublication.PublicationTime);

            if (userPublication.PublicationTime != extendedTimeCalendarHashChain.PublicationData.PublicationTime)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub02);
            }

            return GetSignature(context).AggregationTime != extendedTimeCalendarHashChain.RegistrationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}