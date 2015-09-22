using Guardtime.KSI.Signature.Verification.Rule;
using System;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Internal verification polcy.
    /// </summary>
    public class KeyBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public KeyBasedVerificationPolicy()
        {
            // Check for internal verification
            _firstRule = new CalendarHashChainExistenceRule()
                .OnSuccess(new CalendarAuthenticationRecordExistenceRule()
                    .OnSuccess(new CertificateExistenceRule()
                        .OnSuccess(new CalendarAuthenticationRecordSignatureVerificationRule())));
        }
    }
}
