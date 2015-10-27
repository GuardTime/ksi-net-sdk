using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{

    /// <summary>
    ///     Policy for verifying KSI signature with publication.
    /// </summary>
    public partial class PublicationBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create publication based verification policy and add rules to it.
        /// </summary>
        public PublicationBasedVerificationPolicy()
        {
            // Check for internal verification
            FirstRule = new InternalVerificationPolicy()
                .OnSuccess(new UserProvidedPublicationExistenceRule()
                    .OnSuccess(new UserProvidedPublicationBasedVerificationPolicy())
                    .OnNa(new PublicationsFileVerificationPolicy()));
        }
    }
}