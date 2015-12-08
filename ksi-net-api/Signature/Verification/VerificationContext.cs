using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    ///     Verification context.
    /// </summary>
    public class VerificationContext : IVerificationContext
    {
        /// <summary>
        ///     Create new verification context instance.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        
        public VerificationContext(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new KsiException("Invalid KSI signature: null.");
            }

            Signature = signature;
        }

        /// <summary>
        ///     Get or set document hash.
        /// </summary>
        public DataHash DocumentHash { get; set; }

        /// <summary>
        ///     Get KSI signature.
        /// </summary>
        public IKsiSignature Signature { get; }

        /// <summary>
        ///     Get or set user publication.
        /// </summary>
        public PublicationData UserPublication { get; set; }

        /// <summary>
        ///     Get or set KSI service.
        /// </summary>
        public IKsiService KsiService { get; set; }

        /// <summary>
        ///     Get or set if extending is allowed.
        /// </summary>
        public bool IsExtendingAllowed { get; set; }

        /// <summary>
        ///     Get or set publications file.
        /// </summary>
        public IPublicationsFile PublicationsFile { get; set; }

        /// <summary>
        ///     Get extended latest calendar hash chain.
        /// </summary>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedTimeCalendarHashChain(null);
        }

        // TODO: Cache result and make signature mandatory and unchangeable
        /// <summary>
        ///     Get extended calendar hash chain from given publication time.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            if (KsiService == null)
            {
                throw new KsiException("Invalid KSI service: null.");
            }

            return publicationTime == null
                ? KsiService.Extend(Signature.AggregationTime)
                : KsiService.Extend(Signature.AggregationTime, publicationTime.Value);
        }
    }
}