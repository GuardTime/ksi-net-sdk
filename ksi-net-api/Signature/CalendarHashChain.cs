using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Calendar hash chain TLV element
    /// </summary>
    public sealed class CalendarHashChain : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        ///     Calendar hash chain tag type
        /// </summary>
        public const uint TagType = 0x802;

        private const uint PublicationTimeTagType = 0x1;
        private const uint AggregationTimeTagType = 0x2;
        private const uint InputHashTagType = 0x5;
        private readonly IntegerTag _aggregationTime;
        private readonly List<Link> _chain = new List<Link>();
        private readonly ImprintTag _inputHash;
        private readonly DataHash _outputHash;
        private readonly PublicationData _publicationData;

        private readonly IntegerTag _publicationTime;

        private readonly ulong _registrationTime;

        /// <summary>
        ///     Create new calendar hash chain TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public CalendarHashChain(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new TlvException("Invalid calendar hash chain type(" + Type + ").");
            }

            int publicationTimeCount = 0;
            int aggregationTimeCount = 0;
            int inputHashCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        publicationTimeCount++;
                        break;
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        aggregationTimeCount++;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        inputHashCount++;
                        break;
                    case (uint) LinkDirection.Left:
                    case (uint) LinkDirection.Right:
                        Link chainTag = new Link(this[i]);
                        _chain.Add(chainTag);
                        this[i] = chainTag;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (publicationTimeCount != 1)
            {
                throw new TlvException("Only one publication time must exist in calendar hash chain.");
            }

            if (aggregationTimeCount > 1)
            {
                throw new TlvException("Only one aggregation time is allowed in calendar hash chain.");
            }

            if (inputHashCount != 1)
            {
                throw new TlvException("Only one input hash must exist in calendar hash chain.");
            }

            if (_chain.Count == 0)
            {
                throw new TlvException("Links are missing in calendar hash chain.");
            }

            _registrationTime = CalculateRegistrationTime();
            _outputHash = CalculateOutputHash();
            _publicationData = new PublicationData(_publicationTime.Value, _outputHash);
        }

        /// <summary>
        ///     Get aggregation time
        /// </summary>
        public ulong AggregationTime
        {
            get { return _aggregationTime == null ? _publicationTime.Value : _aggregationTime.Value; }
        }

        /// <summary>
        ///     Get publication time.
        /// </summary>
        public ulong PublicationTime
        {
            get { return _publicationTime.Value; }
        }

        /// <summary>
        ///     Get registration time.
        /// </summary>
        public ulong RegistrationTime
        {
            get { return _registrationTime; }
        }

        /// <summary>
        ///     Get input hash.
        /// </summary>
        public DataHash InputHash
        {
            get { return _inputHash.Value; }
        }

        /// <summary>
        ///     Get output hash.
        /// </summary>
        public DataHash OutputHash
        {
            get { return _outputHash; }
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData
        {
            get { return _publicationData; }
        }

        /// <summary>
        ///     Compare right links if they are equal.
        /// </summary>
        /// <param name="calendarHashChain">calendar hash chain to compare to</param>
        /// <returns>true if right links are equal and on same position</returns>
        public bool AreRightLinksEqual(CalendarHashChain calendarHashChain)
        {
            if (calendarHashChain == null)
            {
                return false;
            }

            if (_chain.Count != calendarHashChain._chain.Count)
            {
                return false;
            }

            for (int i = 0; i < _chain.Count; i++)
            {
                if (calendarHashChain._chain[i].Direction != LinkDirection.Right) continue;

                if (_chain[i] != calendarHashChain._chain[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Calculate output hash.
        /// </summary>
        /// <returns>output hash</returns>
        private DataHash CalculateOutputHash()
        {
            DataHash inputHash = InputHash;
            for (int i = 0; i < _chain.Count; i++)
            {
                DataHash siblingHash = _chain[i].Value;
                if (_chain[i].Direction == LinkDirection.Left)
                {
                    inputHash = HashTogether(siblingHash.Algorithm, inputHash.Imprint, siblingHash.Imprint);
                }

                if (_chain[i].Direction == LinkDirection.Right)
                {
                    inputHash = HashTogether(inputHash.Algorithm, siblingHash.Imprint, inputHash.Imprint);
                }
            }

            return inputHash;
        }

        /// <summary>
        ///     Hash two hashes together with algorithm.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <param name="hashA">hash a</param>
        /// <param name="hashB">hash b</param>
        /// <returns>result hash</returns>
        private DataHash HashTogether(HashAlgorithm algorithm, ICollection<byte> hashA, ICollection<byte> hashB)
        {
            DataHasher hasher = new DataHasher(algorithm);
            hasher.AddData(hashA);
            hasher.AddData(hashB);
            hasher.AddData(new byte[] {0xFF});
            return hasher.GetHash();
        }

        /// <summary>
        ///     Calculate registration time.
        /// </summary>
        /// <returns>registration time</returns>
        /// <exception cref="TlvException">thrown when registration time calculation fails.</exception>
        private ulong CalculateRegistrationTime()
        {
            ulong r = _publicationTime.Value;
            ulong t = 0;
            // iterate over the chain in reverse

            for (int i = _chain.Count - 1; i >= 0; i--)
            {
                if (r <= 0)
                {
                    throw new TlvException("Invalid calendar hash chain shape for publication time.");
                }

                if (_chain[i].Direction == LinkDirection.Left)
                {
                    r = HighBit(r) - 1;
                }
                else
                {
                    t = t + HighBit(r);
                    r = r - HighBit(r);
                }
            }

            if (r != 0)
            {
                throw new TlvException("Calendar hash chain shape inconsistent with publication time.");
            }

            return t;
        }

        /// <summary>
        ///     Calculate highest bit.
        /// </summary>
        /// <param name="n">number to get highest bit from.</param>
        /// <returns>highest bit</returns>
        private static ulong HighBit(ulong n)
        {
            n |= (n >> 1);
            n |= (n >> 2);
            n |= (n >> 4);
            n |= (n >> 8);
            n |= (n >> 16);
            n |= (n >> 32);
            return n - (n >> 1);
        }

        /// <summary>
        ///     Calendar hash chain link object which is imprint containing link direction
        /// </summary>
        private class Link : ImprintTag
        {
            private readonly LinkDirection _direction;

            public Link(TlvTag tag) : base(tag)
            {
                if (tag.Type == (int) LinkDirection.Left)
                {
                    _direction = LinkDirection.Left;
                }

                if (tag.Type == (int) LinkDirection.Right)
                {
                    _direction = LinkDirection.Right;
                }

                if (_direction == 0)
                {
                    throw new TlvException("Invalid calendar hash chain link type(" + Type + ").");
                }
            }

            public LinkDirection Direction
            {
                get { return _direction; }
            }
        }
    }
}