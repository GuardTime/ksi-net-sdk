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
        /// <summary>
        ///     Rule name.
        /// </summary>
        public const string RuleName = "SignaturePublicationRecordPublicationTimeRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            if (context.Signature.PublicationRecord == null)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Ok);
            }

            if (context.Signature.CalendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain is missing in KSI signature.");
            }

            PublicationData publicationRecordPublicationData = context.Signature.PublicationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = context.Signature.CalendarHashChain.PublicationData;

            if (publicationRecordPublicationData.PublicationTime != calendarHashChainPublicationData.PublicationTime)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Int07);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}