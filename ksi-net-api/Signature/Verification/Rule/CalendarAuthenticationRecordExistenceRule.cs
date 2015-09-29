using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that KSI signature contains calendar authentication record.
    /// </summary>
    public sealed class CalendarAuthenticationRecordExistenceRule : VerificationRule
    {
        /// <summary>
        /// Rule name.
        /// </summary>
        public const string RuleName = "CalendarAuthenticationRecordExistenceRule";

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

            return context.Signature.CalendarAuthenticationRecord != null
                ? new VerificationResult(RuleName, VerificationResultCode.Ok)
                : new VerificationResult(RuleName, VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}