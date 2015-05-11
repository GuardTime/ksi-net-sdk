namespace Guardtime.KSI.Trust
{
    public interface IPkiTrustProvider
    {
        string Name { get; }
        void Verify(byte[] signedBytes, byte[] x509SignatureBytes);
    }
}
