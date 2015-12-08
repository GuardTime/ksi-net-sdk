using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that publications file publication hash matches with extender reponse calendar hash chain root hash.
    /// </summary>
    public sealed class PublicationsFilePublicationHashMatchesExtenderResponseRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IPublicationsFile publicationsFile = GetPublicationsFile(context);
            ulong registrationTime = GetCalendarHashChain(GetSignature(context)).RegistrationTime;
            PublicationRecord publicationRecord = GetNearestPublicationRecord(publicationsFile, registrationTime);
            CalendarHashChain extendedTimeCalendarHashChain = GetExtendedTimeCalendarHashChain(context, publicationRecord.PublicationData.PublicationTime);

            return extendedTimeCalendarHashChain.OutputHash != publicationRecord.PublicationData.PublicationHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Pub01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}