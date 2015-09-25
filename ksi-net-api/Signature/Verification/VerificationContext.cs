using System;
using System.Collections.Generic;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    ///     Verification context.
    /// </summary>
    public class VerificationContext : IVerificationContext
    {
        private readonly IKsiSignature _signature;
        private CalendarHashChain _calendarExtendedToHead;
        private DataHash _documentHash;

        private Dictionary<int, CalendarHashChain> _extendedCalendars;
        private bool _extendingAllowed;
        private IKsiService _ksiService;
        private IPublicationsFile _publicationsFile;
        private PublicationData _userPublication;

        public VerificationContext(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("signature");
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

        public PublicationData UserPublication
        {
            get { return _userPublication; }
            set { _userPublication = value; }
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

        public IPublicationsFile PublicationsFile
        {
            get { return _publicationsFile; }
            set { _publicationsFile = value; }
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

            return publicationTime == null
                ? _ksiService.Extend(_signature.AggregationTime)
                : _ksiService.Extend(_signature.AggregationTime, publicationTime.Value);
        }
    }
}