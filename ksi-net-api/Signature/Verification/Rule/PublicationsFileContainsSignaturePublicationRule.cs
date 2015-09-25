using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class PublicationsFileContainsSignaturePublicationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="ArgumentNullException">thrown if context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null");
            }

            IKsiTrustProvider publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null");
            }

            if (context.Signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publications record in signature: null");
            }

            if (!publicationsFile.Contains(context.Signature.PublicationRecord))
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}