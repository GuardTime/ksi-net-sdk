using System;
using System.Collections.Generic;
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
        private readonly IKsiSignature _signature;
        private DataHash _documentHash;

        private IDictionary<int, CalendarHashChain> _extendedCalendars;
        private bool _extendingAllowed;
        private IKsiService _ksiService;
        private IPublicationsFile _publicationsFile;
        private PublicationData _userPublication;

        /// <summary>
        ///     Create new verification context instance.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <exception cref="ArgumentNullException">thrown when signature is null</exception>
        public VerificationContext(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new KsiException("Invalid KSI signature: null.");
            }

            _signature = signature;
        }

        /// <summary>
        ///     Get or set document hash.
        /// </summary>
        public DataHash DocumentHash
        {
            get { return _documentHash; }

            set { _documentHash = value; }
        }

        /// <summary>
        ///     Get KSI signature.
        /// </summary>
        public IKsiSignature Signature
        {
            get { return _signature; }
        }

        /// <summary>
        ///     Get or set user publication.
        /// </summary>
        public PublicationData UserPublication
        {
            get { return _userPublication; }
            set { _userPublication = value; }
        }

        /// <summary>
        ///     Get or set KSI service.
        /// </summary>
        public IKsiService KsiService
        {
            get { return _ksiService; }
            set { _ksiService = value; }
        }

        /// <summary>
        ///     Get or set if extending is allowed.
        /// </summary>
        public bool IsExtendingAllowed
        {
            get { return _extendingAllowed; }
            set { _extendingAllowed = value; }
        }

        /// <summary>
        ///     Get or set publications file.
        /// </summary>
        public IPublicationsFile PublicationsFile
        {
            get { return _publicationsFile; }
            set { _publicationsFile = value; }
        }

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
            if (_ksiService == null)
            {
                throw new KsiException("Invalid KSI service: null.");
            }

            return publicationTime == null
                ? _ksiService.Extend(_signature.AggregationTime)
                : _ksiService.Extend(_signature.AggregationTime, publicationTime.Value);
        }
    }
}