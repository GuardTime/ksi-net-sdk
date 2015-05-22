using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Trust
{
    public interface IKsiTrustProvider
    {
        bool Contains(PublicationRecord publicationRecord);
        X509Certificate FindCertificateById(byte[] certificateId);
        string Name { get; }
        // TODO: Create verification
//        VerificationResult GetVerificationResult();

    }
}
