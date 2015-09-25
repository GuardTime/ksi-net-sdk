namespace Guardtime.KSI.Trust
{
    /// <summary>
    ///     PKI trust provider interface.
    /// </summary>
    public interface IPkiTrustProvider
    {
        /// <summary>
        ///     Verify bytes with x509 signature.
        /// </summary>
        /// <param name="signedBytes"></param>
        /// <param name="signatureBytes"></param>
        void Verify(byte[] signedBytes, byte[] signatureBytes);
    }
}