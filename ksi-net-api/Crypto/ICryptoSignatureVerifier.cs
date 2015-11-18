namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     Crypto signature verifier interface.
    /// </summary>
    public interface ICryptoSignatureVerifier
    {
        /// <summary>
        ///     Verify signed bytes and signature.
        /// </summary>
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">other data</param>
        void Verify(byte[] signedBytes, byte[] signatureBytes, CryptoSignatureVerificationData data);
    }
}