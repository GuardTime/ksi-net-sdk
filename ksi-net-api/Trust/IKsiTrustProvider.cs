using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Trust
{
    public interface IKsiTrustProvider
    {
        bool Contains(PublicationRecord publicationRecord);
//        Certificate FindCertificateById(byte[] certificateId);
        string Name { get; }
//        VerificationResult GetVerificationResult();

    }
}
