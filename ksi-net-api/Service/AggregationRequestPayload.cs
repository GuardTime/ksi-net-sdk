using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation request payload.
    /// </summary>
    public sealed class AggregationRequestPayload : AggregationPduPayload
    {
        private readonly RawTag _config;
        private readonly ImprintTag _requestHash;
        private readonly IntegerTag _requestId;
        private readonly IntegerTag _requestLevel;

        /// <summary>
        ///     Create extend request payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public AggregationRequestPayload(TlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationRequestPayload.TagType)
            {
                throw new TlvException("Invalid aggregation request payload type(" + Type + ").");
            }

            int requestIdCount = 0;
            int requestHashCount = 0;
            int requestLevelCount = 0;
            int configCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.AggregationRequestPayload.RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        this[i] = _requestId;
                        requestIdCount++;
                        break;
                    case Constants.AggregationRequestPayload.RequestHashTagType:
                        _requestHash = new ImprintTag(this[i]);
                        this[i] = _requestHash;
                        requestHashCount++;
                        break;
                    case Constants.AggregationRequestPayload.RequestLevelTagType:
                        _requestLevel = new IntegerTag(this[i]);
                        this[i] = _requestLevel;
                        requestLevelCount++;
                        break;
                    case Constants.AggregationRequestPayload.ConfigTagType:
                        _config = new RawTag(this[i]);
                        this[i] = _config;
                        configCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Only one request id must exist in aggregation request payload.");
            }

            if (requestHashCount != 1)
            {
                throw new TlvException("Only one request hash must exist in aggregation request payload.");
            }

            if (requestLevelCount > 1)
            {
                throw new TlvException(
                    "Only one request level is allowed in aggregation request payload.");
            }

            if (configCount > 1)
            {
                throw new TlvException("Only one config tag is allowed in aggregation request payload.");
            }
        }

        /// <summary>
        ///     Create aggregation request payload from data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <exception cref="TlvException">thrown when data hash is null</exception>
        public AggregationRequestPayload(DataHash hash) : base(Constants.AggregationRequestPayload.TagType, false, false, new List<TlvTag>())
        {
            if (hash == null)
            {
                throw new TlvException("Invalid data hash: null.");
            }

            _requestId = new IntegerTag(Constants.AggregationRequestPayload.RequestIdTagType, false, false, Util.GetRandomUnsignedLong());
            AddTag(_requestId);

            _requestHash = new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false, hash);
            AddTag(_requestHash);
        }

        /// <summary>
        ///     Get request hash.
        /// </summary>
        public DataHash RequestHash
        {
            get { return _requestHash.Value; }
        }

        /// <summary>
        ///     Is config requested.
        /// </summary>
        public bool IsConfigRequested
        {
            get { return _config == null; }
        }

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId
        {
            get { return _requestId.Value; }
        }

        /// <summary>
        ///     Get request level if it exists.
        /// </summary>
        public ulong? RequestLevel
        {
            get { return _requestLevel == null ? (ulong?)null : _requestLevel.Value; }
        }
    }
}