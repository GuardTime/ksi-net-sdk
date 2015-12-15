using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that publications file publication time matches with extender response calendar hash chain registration
    ///     time.
    /// </summary>
    public sealed class PublicationsFilePublicationTimeMatchesExtenderResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            ulong registrationTime = GetCalendarHashChain(signature).RegistrationTime;
            PublicationRecord publicationRecord = GetNearestPublicationRecord(GetPublicationsFile(context), registrationTime);
            CalendarHashChain extendedTimeCalendarHashChain = GetExtendedTimeCalendarHashChain(context, publicationRecord.PublicationData.PublicationTime);

            if (publicationRecord.PublicationData.PublicationTime != extendedTimeCalendarHashChain.PublicationTime)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub02);
            }

            return signature.AggregationTime != extendedTimeCalendarHashChain.RegistrationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}