namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// Certificate subject RDN selector.
    /// </summary>
    public interface ICertificateSubjectRdnSelector
    {
        /// <summary>
        /// Checks if certificate contains rdn selectors
        /// </summary>
        /// <param name="certificate">certificate to check</param>
        /// <returns></returns>
        bool IsMatch(object certificate);
    }
}