using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Policy for verifying KSI signature with PKI.
    /// </summary>
    public class KeyBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create key based verification policy and add rules to it.
        /// </summary>
        public KeyBasedVerificationPolicy(X509Certificate2Collection trustAnchors, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            if (trustAnchors == null)
            {
                throw new ArgumentNullException(nameof(trustAnchors));
            }

            // Check for internal verification
            FirstRule = new InternalVerificationPolicy()
                .OnSuccess(new CalendarHashChainExistenceRule()
                    .OnSuccess(new CalendarAuthenticationRecordExistenceRule()
                        .OnSuccess(new CertificateExistenceRule()
                            .OnSuccess(new CalendarAuthenticationRecordSignatureVerificationRule(trustAnchors, certificateRdnSelector)))));
        }
    }
}