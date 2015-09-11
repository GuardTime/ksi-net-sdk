using System;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Signature.Verification.Rule.Publication;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public class PublicationVerificationPolicy : IPolicy
    {
        private readonly IRule _startRule ;

        public PublicationVerificationPolicy()
        {
            IRule rule = new SignatureExtendingPermissionRule()
                .OnSuccess(null);

            _startRule = new UserPublicationExistanceRule()
                .OnSuccess(new SignaturePublicationExistanceRule()
                    .OnSuccess(new PublicationsEqualsRule())
                    .OnNa(new SignatureCreatedBeforeUserPublicationRule()
                        .OnSuccess(rule)))
                .OnNa(new PublicationsFileHasExtendablePublicationRule()
                    .OnSuccess(rule));
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
