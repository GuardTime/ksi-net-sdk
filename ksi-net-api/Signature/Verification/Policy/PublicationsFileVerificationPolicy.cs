using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{

    public partial class PublicationBasedVerificationPolicy
    {
        /// <summary>
        ///     Policy for verifying KSI signature with publications file.
        /// </summary>
        private class PublicationsFileVerificationPolicy : VerificationPolicy
        {
            /// <summary>
            ///     Create publications file verification policy instance.
            /// </summary>
            public PublicationsFileVerificationPolicy()
            {
                FirstRule = new SignaturePublicationRecordExistenceRule()
                    .OnSuccess(new PublicationsFileContainsSignaturePublicationRule())
                    .OnNa(new ExtendingPermittedVerificationRule()
                        .OnSuccess(new PublicationsFilePublicationHashMatchesExtenderResponseRule()
                            .OnSuccess(new PublicationsFilePublicationTimeMatchesExtenderResponseRule()
                                .OnSuccess(new PublicationsFileExtendedSignatureInputHashRule()))));
            }
        }
    }
}