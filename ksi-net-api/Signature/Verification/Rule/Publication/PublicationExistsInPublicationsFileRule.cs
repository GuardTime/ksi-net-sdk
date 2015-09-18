using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class PublicationExistsInPublicationsFileRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            PublicationsFile publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new InvalidOperationException("Invalid publications file: null");
            }

            if (!publicationsFile.Contains(context.PublicationRecord))
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}