using System;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification context interface.
    /// </summary>
    public interface IVerificationContext
    {
        /// <summary>
        /// Get document hash.
        /// </summary>
        DataHash DocumentHash
        {
            get;
        }

        /// <summary>
        /// Get signature.
        /// </summary>
        KsiSignature Signature
        {
            get;
        }

        /// <summary>
        /// Get user publication.
        /// </summary>
        PublicationData UserPublication
        {
            get;
        }

        /// <summary>
        /// Get KSI service.
        /// </summary>
        IKsiService KsiService
        {
            get;
        }

        /// <summary>
        /// Is extending allowed.
        /// </summary>
        bool IsExtendingAllowed
        {
            get;
        }

        /// <summary>
        /// Get publications file.
        /// </summary>
        PublicationsFile PublicationsFile
        {
            get;
        }

        /// <summary>
        /// Get extended latest calendar hash chain.
        /// </summary>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain GetExtendedLatestCalendarHashChain();

        // TODO: Cache result and make signature mandatory and unchangeable
        /// <summary>
        /// Get extended calendar hash chain from given publication time.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime);
    }
}