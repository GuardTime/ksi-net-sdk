/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using NLog;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Calendar hash chain TLV element
    /// </summary>
    public sealed class CalendarHashChain : CompositeTag
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private IntegerTag _aggregationTime;
        private readonly List<Link> _chain = new List<Link>();
        private ImprintTag _inputHash;
        private IntegerTag _publicationTime;
        private DataHash _outputHash;
        private PublicationData _publicationData;
        private ulong? _registrationTime;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.CalendarHashChain.TagType;

        /// <summary>
        ///     Create new calendar hash chain TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CalendarHashChain(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.CalendarHashChain.PublicationTimeTagType:
                    return _publicationTime = GetIntegerTag(childTag);
                case Constants.CalendarHashChain.AggregationTimeTagType:
                    return _aggregationTime = GetIntegerTag(childTag);
                case Constants.CalendarHashChain.InputHashTagType:
                    return _inputHash = GetImprintTag(childTag);
                case (uint)LinkDirection.Left:
                case (uint)LinkDirection.Right:
                    Link chainTag = childTag as Link ?? new Link(childTag);
                    _chain.Add(chainTag);
                    return chainTag;
                default:
                    return base.ParseChild(childTag);
            }
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate(TagCounter tagCounter)
        {
            base.Validate(tagCounter);

            if (tagCounter[Constants.CalendarHashChain.PublicationTimeTagType] != 1)
            {
                throw new TlvException("Exactly one publication time must exist in calendar hash chain.");
            }

            if (tagCounter[Constants.CalendarHashChain.AggregationTimeTagType] > 1)
            {
                throw new TlvException("Only one aggregation time is allowed in calendar hash chain.");
            }

            if (tagCounter[Constants.CalendarHashChain.InputHashTagType] != 1)
            {
                throw new TlvException("Exactly one input hash must exist in calendar hash chain.");
            }

            if (_chain.Count == 0)
            {
                throw new TlvException("Links are missing in calendar hash chain.");
            }
        }

        /// <summary>
        ///     Get aggregation time
        /// </summary>
        public ulong AggregationTime => _aggregationTime?.Value ?? _publicationTime.Value;

        /// <summary>
        ///     Get publication time.
        /// </summary>
        public ulong PublicationTime => _publicationTime.Value;

        /// <summary>
        ///     Get registration time.
        /// </summary>
        public ulong RegistrationTime => _registrationTime ?? (_registrationTime = CalculateRegistrationTime()).Value;

        /// <summary>
        ///     Get input hash.
        /// </summary>
        public DataHash InputHash => _inputHash.Value;

        /// <summary>
        ///     Get output hash.
        /// </summary>
        public DataHash OutputHash => _outputHash ?? (_outputHash = CalculateOutputHash());

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData => _publicationData ?? (_publicationData = new PublicationData(_publicationTime.Value, OutputHash));

        private static IEnumerable<Link> GetRightLinksEnumerable(IList<Link> chain)
        {
            for (int i = 0; i < chain.Count; i++)
            {
                if (chain[i].Direction == LinkDirection.Right)
                {
                    yield return chain[i];
                }
            }
        }

        /// <summary>
        ///     Compare right links if they are equal.
        /// </summary>
        /// <param name="calendarHashChain">calendar hash chain to compare to</param>
        /// <returns>true if right links are equal and in same order</returns>
        public bool AreRightLinksEqual(CalendarHashChain calendarHashChain)
        {
            IEnumerator<Link> currentEnumerator = GetRightLinksEnumerable(_chain).GetEnumerator();
            IEnumerator<Link> externalEnumerator = GetRightLinksEnumerable(calendarHashChain._chain).GetEnumerator();
            Link currentLink = currentEnumerator.MoveNext() ? currentEnumerator.Current : null;
            Link externalLink = externalEnumerator.MoveNext() ? externalEnumerator.Current : null;

            while (currentLink != null || externalLink != null)
            {
                if (currentLink != externalLink)
                {
                    return false;
                }

                currentLink = currentEnumerator.MoveNext() ? currentEnumerator.Current : null;
                externalLink = externalEnumerator.MoveNext() ? externalEnumerator.Current : null;
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
            foreach (Link link in _chain)
            {
                DataHash siblingHash = link.Value;

                switch (link.Direction)
                {
                    case LinkDirection.Left:
                        inputHash = GetStepHash(siblingHash.Algorithm, inputHash.Imprint, siblingHash.Imprint);
                        break;
                    case LinkDirection.Right:
                        inputHash = GetStepHash(inputHash.Algorithm, siblingHash.Imprint, inputHash.Imprint);
                        break;
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
        private static DataHash GetStepHash(HashAlgorithm algorithm, byte[] hashA, byte[] hashB)
        {
            IDataHasher hasher = KsiProvider.CreateDataHasher(algorithm);
            hasher.AddData(hashA);
            hasher.AddData(hashB);
            hasher.AddData(new byte[] { 0xFF });
            return hasher.GetHash();
        }

        /// <summary>
        ///     Calculate registration time.
        /// </summary>
        /// <returns>registration time</returns>
        private ulong CalculateRegistrationTime()
        {
            ulong r = _publicationTime.Value;
            ulong t = 0;
            // iterate over the chain in reverse

            for (int i = _chain.Count - 1; i >= 0; i--)
            {
                if (r <= 0)
                {
                    Logger.Warn("Invalid calendar hash chain shape for publication time. Cannot calculate registration time.");
                    return 0;
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
                Logger.Warn("Calendar hash chain shape inconsistent with publication time. Cannot calculate registration time.");
                return 0;
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
            public Link(ITlvTag tag) : base(tag)
            {
                CheckTagType((uint)LinkDirection.Right, (uint)LinkDirection.Left);

                switch (Type)
                {
                    case (uint)LinkDirection.Left:
                        Direction = LinkDirection.Left;
                        break;
                    case (uint)LinkDirection.Right:
                        Direction = LinkDirection.Right;
                        break;
                }
            }

            public LinkDirection Direction { get; }
        }
    }
}