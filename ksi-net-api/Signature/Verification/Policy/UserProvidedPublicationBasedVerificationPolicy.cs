using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Policy for verifying KSI signature with user provided publication.
    /// </summary>
    public class UserProvidedPublicationBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create user provided publication based verification policy with given rules.
        /// </summary>
        public UserProvidedPublicationBasedVerificationPolicy()
        {
            VerificationRule verificationRule = new ExtendingPermittedVerificationRule()
                .OnSuccess(new UserProvidedPublicationHashMatchesExtendedResponseRule()
                    .OnSuccess(new UserProvidedPublicationTimeMatchesExtendedResponseRule()
                        .OnSuccess(new UserProvidedPublicationExtendedSignatureInputHashRule())));

            FirstRule = new UserProvidedPublicationExistenceRule()
                .OnSuccess(new SignaturePublicationRecordExistenceRule()
                    .OnSuccess(new UserProvidedPublicationVerificationRule())
                    .OnNa(new UserProvidedPublicationCreationTimeVerificationRule()
                        .OnSuccess(verificationRule)));
        }
    }
}