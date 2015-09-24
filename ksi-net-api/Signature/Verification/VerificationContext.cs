using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification context.
    /// </summary>
    public class VerificationContext : IVerificationContext
    {
        private readonly KsiSignature _signature;
        private DataHash _documentHash;
        private PublicationData _userPublication;
        private PublicationsFile _publicationsFile;

        private Dictionary<int, CalendarHashChain> _extendedCalendars;
        private CalendarHashChain _calendarExtendedToHead;
        private IKsiService _ksiService;
        private bool _extendingAllowed;

        /// <summary>
        /// Get or set document hash.
        /// </summary>
        public DataHash DocumentHash
        {
            get
            {
                return _documentHash;
            }

            set
            {
                _documentHash = value;
            }
        }

        /// <summary>
        /// Get KSI signature.
        /// </summary>
        public KsiSignature Signature
        {
            get
            {
                return _signature;
            }
        }

        public PublicationData UserPublication
        {
            get { return _userPublication; }
            set
            {
                _userPublication = value;
            }
        }        

        public IKsiService KsiService
        {
            get { return _ksiService; }
            set { _ksiService = value; }
        }

        public bool IsExtendingAllowed
        {
            get { return _extendingAllowed; }
            set { _extendingAllowed = value; }
        }

        public PublicationsFile PublicationsFile
        {
            get { return _publicationsFile; }
            set { _publicationsFile = value; }
        }

        public VerificationContext(KsiSignature signature)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }

            _signature = signature;
        }

        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedTimeCalendarHashChain(null);
        }

        // TODO: Cache result and make signature mandatory and unchangeable
        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            if (_ksiService == null)
            {
                throw new InvalidOperationException("Invalid KSI service: null");
            }

            return publicationTime == null ? _ksiService.Extend(_signature.AggregationTime) : _ksiService.Extend(_signature.AggregationTime, publicationTime.Value);
        }

    }
}