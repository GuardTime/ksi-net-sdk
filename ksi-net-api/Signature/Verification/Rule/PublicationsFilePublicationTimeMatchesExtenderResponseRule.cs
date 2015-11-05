using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that publications file publication time matches with extender response calendar hash chain registration
    ///     time.
    /// </summary>
    public sealed class PublicationsFilePublicationTimeMatchesExtenderResponseRule : VerificationRule
    {
        /// <summary>
        ///     Rule name.
        /// </summary>
        public const string RuleName = "PublicationsFilePublicationTimeMatchesExtenderResponseRule";

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

            IPublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null.");
            }

            CalendarHashChain signatureCalendarHashChain = context.Signature.CalendarHashChain;
            if (signatureCalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in KSI signature: null.");
            }

            PublicationRecord publicationRecord =
                publicationsFile.GetNearestPublicationRecord(signatureCalendarHashChain.RegistrationTime);
            if (publicationRecord == null)
            {
                throw new KsiVerificationException(
                    "No publication record found in publications file after registration time: " +
                    signatureCalendarHashChain.RegistrationTime + ".");
            }

            CalendarHashChain extendedTimeCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(publicationRecord.PublicationData.PublicationTime);
            if (extendedTimeCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Received invalid extended calendar hash chain from context extension function: null.");
            }

            if (publicationRecord.PublicationData.PublicationTime != extendedTimeCalendarHashChain.PublicationTime)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Pub02);
            }

            if (context.Signature.AggregationTime != extendedTimeCalendarHashChain.RegistrationTime)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Pub02);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}