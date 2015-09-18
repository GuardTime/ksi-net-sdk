using System;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Signature.Verification.Rule.Publication;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public class PublicationsFileVerificationPolicy : IPolicy
    {
        private readonly IRule _startRule ;

        public PublicationsFileVerificationPolicy()
        {
            IRule rule = new SignatureExtendingPermissionRule()
                .OnSuccess(new PublicationsFilePublicationHashMatchesExtenderResponseRule()
                    .OnSuccess(new PublicationsFilePublicationTimeMatchesExtendedResponseRule()
                        .OnSuccess(new PublicationsFileExtendedSignatureInputHashRule())));

            _startRule = new SignaturePublicationExistanceRule()
                .OnSuccess(new PublicationExistsInPublicationsFileRule())
                // TODO: Fix onSuccess, it should fail when publication record exists
                .OnNa(new SignaturePublicationExistanceRule()
                    .OnNa(rule));
        }

        public bool Verify(VerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            IRule rule = _startRule ?? IRule.Empty;
            while (rule != null)
            {
                VerificationResult result = rule.Verify(context);
                Console.WriteLine("Rule {0}: {1}", rule.GetType().Name, result);
                rule = rule.NextRule(result);
            }

            return true;
        }
    }
}
