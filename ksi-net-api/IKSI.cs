using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI
{
    /// <summary>
    ///     Simple implementation of KSI services.
    /// </summary>
    public interface IKsi
    {
        /// <summary>
        ///     Sign document hash.
        /// </summary>
        /// <param name="hash">document hash</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Sign(DataHash hash);

        /// <summary>
        ///     Extend signature to calendar head.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature ExtendToHead(IKsiSignature signature);

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(IKsiSignature signature, PublicationRecord publicationRecord);

        /// <summary>
        ///     Get publications file.
        /// </summary>
        /// <returns>publications file</returns>
        IPublicationsFile GetPublicationsFile();

        /// <summary>
        /// Verify keyless signature.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <param name="policy">verification policy</param>
        /// <returns>verification result</returns>
        VerificationResult Verify(IVerificationContext context, VerificationRule policy);
    }
}