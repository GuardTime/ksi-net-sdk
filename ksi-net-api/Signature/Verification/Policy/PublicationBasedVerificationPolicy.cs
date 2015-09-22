using Guardtime.KSI.Signature.Verification.Rule;
using System;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Internal verification polcy.
    /// </summary>
    public class PublicationBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public PublicationBasedVerificationPolicy()
        {
            // Check for internal verification
            _firstRule = new UserProvidedPublicationExistenceRule()
                .OnSuccess(new UserProvidedPublicationBasedVerificationPolicy())
                .OnNa(new PublicationsFileVerificationPolicy());
        }


    }
}
