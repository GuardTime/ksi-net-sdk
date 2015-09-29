using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI
{
    /// <summary>
    ///     Simple implementation of KSI services.
    /// </summary>
    public class Ksi
    {
        private readonly IKsiService _ksiService;

        /// <summary>
        ///     Create new KSI instance.
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        /// <exception cref="KsiException">thrown when KSI service is null</exception>
        public Ksi(IKsiService ksiService)
        {
            if (ksiService == null)
            {
                throw new KsiException("KSI service cannot be null.");
            }
            _ksiService = ksiService;
        }

        /// <summary>
        ///     Sign document hash.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// DataHash hash;
        /// KsiService ksiService;
        /// 
        /// IKsiSignature signature = ksiService.Sign(hash);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="hash">document hash</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash)
        {
            if (hash == null)
            {
                throw new KsiException("Document hash cannot be null.");
            }

            return _ksiService.Sign(hash);
        }

        /// <summary>
        ///     Extend signature to calendar head.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiService ksiService;
        /// IKsiSignature signature;
        /// IPublicationsFile publicationsFile.
        /// 
        /// CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime, publicationsFile.GetLatestPublication().PublicationData.PublicationTime);
        /// IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        /// <exception cref="KsiException">thrown when invalid data is supplied</exception>
        public IKsiSignature ExtendToHead(IKsiSignature signature)
        {
            return Extend(signature, GetPublicationsFile().GetLatestPublication());
        }

        /// <summary>
        ///     Extend signature to publication.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiService ksiService;
        /// IKsiSignature signature;
        /// PublicationRecord publicationRecord;
        /// 
        /// CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
        /// IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication</param>
        /// <returns>extended KSI signature</returns>
        /// <exception cref="KsiException">thrown when invalid data is supplied</exception>
        public IKsiSignature Extend(IKsiSignature signature, PublicationRecord publicationRecord)
        {
            if (signature == null)
            {
                throw new KsiException("KSI signature cannot be null.");
            }

            if (publicationRecord == null)
            {
                throw new KsiException("Publication record cannot be null.");
            }

            CalendarHashChain calendarHashChain = _ksiService.Extend(signature.AggregationTime,
                publicationRecord.PublicationData.PublicationTime);
            return signature.Extend(calendarHashChain, publicationRecord);
        }

        /// <summary>
        ///     Get publications file.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiService ksiService;
        /// 
        /// IPublicationsFile publicationsFile = ksiService.GetPublicationsFile();
        /// </code>
        ///     </example>
        /// </summary>
        /// <returns>publications file</returns>
        /// <exception cref="KsiException">thrown when null is returned from KSI service</exception>
        public IPublicationsFile GetPublicationsFile()
        {
            IPublicationsFile publicationsFile = _ksiService.GetPublicationsFile();
            if (publicationsFile == null)
            {
                throw new KsiException("Publications file cannot be null.");
            }

            return publicationsFile;
        }

        /// <summary>
        /// Verify keyless signature.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <param name="policy">verification rule</param>
        /// <returns>verification result</returns>
        /// <exception cref="KsiException">thrown when verification policy is null</exception>
        public VerificationResult Verify(IVerificationContext context, VerificationRule policy)
        {
            if (policy == null)
            {
                throw new KsiException("Invalid verification rule: null.");
            }

            return policy.Verify(context);
        }
    }
}