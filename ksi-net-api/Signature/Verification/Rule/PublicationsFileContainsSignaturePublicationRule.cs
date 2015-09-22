using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class PublicationsFileContainsSignaturePublicationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            PublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new InvalidOperationException("Invalid publications file: null");
            }

            if (!publicationsFile.Contains(context.Signature.PublicationRecord))
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}