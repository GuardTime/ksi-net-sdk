using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Trust
{
    /// <summary>
    ///     KSI trust provider interface.
    /// </summary>
    public interface IKsiTrustProvider
    {
        /// <summary>
        ///     Get KSI trust provider name.
        /// </summary>
        string Name { get; }

        /// <summary>
        ///     KSI trust provider contains given publication record.
        /// </summary>
        /// <param name="publicationRecord">publication record</param>
        /// <returns>true if publication record exists in ksi trust provider</returns>
        bool Contains(PublicationRecord publicationRecord);

        /// <summary>
        ///     Find X509 certificate in KSI trust provider.
        /// </summary>
        /// <param name="certificateId">certificate ID</param>
        /// <returns>x509 certificate contained in trust provider</returns>
        X509Certificate2 FindCertificateById(byte[] certificateId);
    }
}