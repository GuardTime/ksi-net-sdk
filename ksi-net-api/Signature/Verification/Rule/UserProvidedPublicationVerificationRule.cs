using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication equals to publication in KSI signature.
    /// </summary>
    public sealed class UserProvidedPublicationVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publication record in KSI signature: null.");
            }

            PublicationData userPublication = GetUserPublication(context);
            PublicationData signaturePublication = GetPublicationRecord(signature).PublicationData;

            if (userPublication == signaturePublication)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            Logger.Debug("User provided publication does not equal to signature publication.{0}User provided publication:{1}{2}{3}Signature publication:{4}{5}",
                Environment.NewLine,
                Environment.NewLine,
                userPublication,
                Environment.NewLine,
                Environment.NewLine,
                signaturePublication);

            return new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}