using System;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Publications file verification policy.
    /// </summary>
    public class PublicationsFileVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        /// Create publications file verification policy instance.
        /// </summary>
        public PublicationsFileVerificationPolicy()
        {
            _firstRule = new SignaturePublicationRecordExistenceRule()
                .OnSuccess(new PublicationsFileContainsSignaturePublicationRule())
                // TODO: Fix onSuccess, it should fail when publication record exists
                .OnNa(new ExtendingPermittedVerificationRule()
                    .OnSuccess(new PublicationsFilePublicationHashMatchesExtenderResponseRule()
                        .OnSuccess(new PublicationsFilePublicationTimeMatchesExtenderResponseRule()
                            .OnSuccess(new PublicationsFileExtendedSignatureInputHashRule()))));
        }
    }
}
