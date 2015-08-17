using Guardtime.KSI.Publication;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Hashing;
using System.Collections.ObjectModel;
using System;

namespace Guardtime.KSI.Signature
{

    /// <summary>
    /// KSI Signature TLV element
    /// </summary>
    public class KsiSignatureDo : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// KSI signature tag type
        /// </summary>
        public const uint TagType = 0x800;

        private readonly List<AggregationHashChain> _aggregationHashChainCollection = new List<AggregationHashChain>();
        private readonly CalendarHashChain _calendarChain;
        private readonly PublicationRecord _publicationRecord;
        private readonly AggregationAuthenticationRecord _aggregationAuthenticationRecord;
        private readonly CalendarAuthenticationRecord _calendarAuthenticationRecord;
        private readonly Rfc3161Record _rfc3161Record;

        /// <summary>
        /// Get aggregation time
        /// </summary>
        public ulong AggregationTime
        {
            get
            {
                return _calendarChain.AggregationTime;
            }
        }

        /// <summary>
        /// Get RFC 3161 record
        /// </summary>
        public Rfc3161Record Rfc3161Record
        {
            get
            {
                return _rfc3161Record;
            }
        }

        /// <summary>
        /// Is signature RFC 3161 format
        /// </summary>
        public bool IsRfc3161Signature
        {
            get
            {
                return _rfc3161Record != null;
            }
        }

        /// <summary>
        /// Get Calendar Hash Chain
        /// </summary>
        public CalendarHashChain CalendarHashChain {
            get
            {
                return _calendarChain;
            }
        }

        // Order aggregation chain list to correct order
        // TODO: Create interface for tags list
        /// <summary>
        /// Create new KSI signature TLV element from TLV element
        /// </summary>
        /// <param name="tagList">TLV tag list</param>
        public KsiSignatureDo(List<TlvTag> tagList) : this(new KsiSignatureDo(0x800, false, false, tagList))
        {
        }

        // TODO: Better solution
        /// <summary>
        /// Constructor for creating current object for decoding
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV value</param>
        private KsiSignatureDo(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
        }

        /// <summary>
        /// Create new KSI signature TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public KsiSignatureDo(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationHashChain.TagType:
                        AggregationHashChain aggregationChainTag = new AggregationHashChain(this[i]);
                        _aggregationHashChainCollection.Add(aggregationChainTag);
                        this[i] = aggregationChainTag;
                        break;
                    case CalendarHashChain.TagType:
                        _calendarChain = new CalendarHashChain(this[i]);
                        this[i] = _calendarChain;
                        break;
                    case PublicationRecord.TagTypeSignature:
                        _publicationRecord = new PublicationRecord(this[i]);
                        this[i] = _publicationRecord;
                        break;
                    case AggregationAuthenticationRecord.TagType:
                        _aggregationAuthenticationRecord = new AggregationAuthenticationRecord(this[i]);
                        this[i] = _aggregationAuthenticationRecord;
                        break;
                    case CalendarAuthenticationRecord.TagType:
                        _calendarAuthenticationRecord = new CalendarAuthenticationRecord(this[i]);
                        this[i] = _calendarAuthenticationRecord;
                        break;
                    case Rfc3161Record.TagType:
                        _rfc3161Record = new Rfc3161Record(this[i]);
                        this[i] = _rfc3161Record;
                        break;
                }
            }

            _aggregationHashChainCollection.Sort(new AggregationHashChain.ChainIndexOrdering());
        }

        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _aggregationHashChainCollection.AsReadOnly();
        }

        /// <summary>
        /// Get aggregation hash chain output hash
        /// </summary>
        /// <returns>output hash</returns>
        public DataHash GetAggregationHashChainRootHash()
        {
            AggregationHashChain.ChainResult lastResult = new AggregationHashChain.ChainResult(0, null);
            for (int i = 0; i < _aggregationHashChainCollection.Count; i++)
            {
                lastResult = _aggregationHashChainCollection[i].GetOutputHash(lastResult.Level);
            }

            return lastResult.Hash;
        }

        /// <summary>
        /// Check TLV structure.
        /// </summary>
        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid signature type: " + Type);
            }

            uint[] tags = new uint[6];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationHashChain.TagType:
                        tags[0]++;
                        break;
                    case CalendarHashChain.TagType:
                        tags[1]++;
                        break;
                    case PublicationRecord.TagTypeSignature:
                        tags[2]++;
                        break;
                    case AggregationAuthenticationRecord.TagType:
                        tags[3]++;
                        break;
                    case CalendarAuthenticationRecord.TagType:
                        tags[4]++;
                        break;
                    case Rfc3161Record.TagType:
                        tags[5]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] == 0)
            {
                throw new InvalidTlvStructureException("Aggregation hash chains must exist in signature data object");
            }

            if (tags[1] > 1)
            {
                throw new InvalidTlvStructureException("Only one calendar hash chain is allowed in signature data object");
            }

            if (tags[1] == 0 && (tags[2] != 0 || tags[4] != 0))
            {
                throw new InvalidTlvStructureException("No publication record or calendar authentication record is allowed in signature data object if there is no calendar hash chain");
            }

            if ((tags[2] != 0 || tags[4] != 0) && (tags[2] != 1 || tags[4] != 0) && (tags[2] != 0 || tags[4] != 1))
            {
                throw new InvalidTlvStructureException("Only one from publication record or calendar authentication record is allowed in signature data object");
            }


            if (tags[5] > 1)
            {
                throw new InvalidTlvStructureException("Only one RFC 3161 record is allowed in signature data object");
            }

            // TODO: Aggregation hash chain if defined
        }
    }
}