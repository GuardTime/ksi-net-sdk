using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if KSI signature calendar hash chain publication data matches publication record publication data. If
    ///     publication record is missing, <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class SignaturePublicationRecordPublicationTimeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (signature.PublicationRecord == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            PublicationData publicationRecordPublicationData = signature.PublicationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = GetCalendarHashChain(signature).PublicationData;

            return publicationRecordPublicationData.PublicationTime != calendarHashChainPublicationData.PublicationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int07)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}