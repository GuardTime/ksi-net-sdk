using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
        private KsiSignature _signature;
        private DataHash _documentHash;
        private PublicationData _userPublication;

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
        /// Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain
        {
            get
            {
                return _signature == null ? null : _signature.CalendarHashChain;
            }
        }

        /// <summary>
        /// Get calendar authentication record.
        /// </summary>
        public CalendarAuthenticationRecord CalendarAuthenticationRecord
        {
            get
            {
                return _signature == null ? null : _signature.CalendarAuthenticationRecord;
            }
        }

        /// <summary>
        /// Get publication record.
        /// </summary>
        public PublicationRecord PublicationRecord
        {
            get
            {
                return _signature == null ? null : _signature.PublicationRecord;
            }
        }

        /// <summary>
        /// Get or set KSI signature.
        /// </summary>
        public KsiSignature Signature
        {
            get
            {
                return _signature;
            }

            set
            {
                _signature = value;
            }
        }

        public PublicationData UserPublication
        {
            get { return _userPublication; }
            set {
                _userPublication = value;
            }
        }

        /// <summary>
        /// Get aggregation hash chains collection.
        /// </summary>
        /// <returns>aggregation hash chains collection</returns>
        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _signature == null ? null : _signature.GetAggregationHashChains();
        }

        /// <summary>
        /// Get aggregation hash chains root hash
        /// </summary>
        /// <returns>output hash</returns>
        public DataHash GetAggregationHashChainRootHash()
        {
            return _signature == null ? null : _signature.GetAggregationHashChainRootHash();
        }

        public IKsiService KsiService
        {
            get { return _ksiService; }
            set { _ksiService = value; }
        }

        public bool ExtendingAllowed
        {
            get { return _extendingAllowed; }
            set { _extendingAllowed = value; }
        }

        // TODO: Better solution?
        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedTimeCalendarHashChain(null);
        }

        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            if (_ksiService == null)
            {
                throw new InvalidOperationException("Cannot extend when KSI service is missing");
            }

            if (_signature == null)
            {
                throw new InvalidOperationException("No signature to extend");
            }

            return publicationTime == null ? _ksiService.Extend(_signature.AggregationTime) : _ksiService.Extend(_signature.AggregationTime, publicationTime.Value);
        }

    }
}