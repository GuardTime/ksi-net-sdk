using System;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public class UserProvidedPublicationBasedVerificationPolicy : VerificationPolicy
    {
        public UserProvidedPublicationBasedVerificationPolicy()
        {
            VerificationRule _verificationRule = new ExtendingPermittedVerificationRule()
                .OnSuccess(new UserProvidedPublicationHashMatchesExtendedResponseRule()
                    .OnSuccess(new UserProvidedPublicationTimeMatchesExtendedResponseRule()
                        .OnSuccess(new UserProvidedPublicationExtendedSignatureInputHashRule())));

            _firstRule = new UserProvidedPublicationExistenceRule()
                .OnSuccess(new SignaturePublicationRecordExistenceRule()
                    .OnSuccess(new UserProvidedPublicationVerificationRule())
                    .OnNa(new UserProvidedPublicationCreationTimeVerificationRule()
                        .OnSuccess(_verificationRule)));
        }
    }
}
