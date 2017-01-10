/*
 * Copyright 2013-2016 Guardtime, Inc.
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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Aggregation hash chain TLV element.
    /// </summary>
    public sealed partial class AggregationHashChain : CompositeTag
    {
        private IntegerTag _aggrAlgorithmId;
        private IntegerTag _aggregationTime;
        private readonly List<Link> _links = new List<Link>();
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private RawTag _inputData;
        private ImprintTag _inputHash;
        private Dictionary<AggregationHashChainResult, AggregationHashChainResult> _aggregationHashChainResultCache;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregationHashChain.TagType;

        /// <summary>
        ///  Create new aggregation hash chain TLV element from TLV element.
        /// </summary>
        /// <param name="aggreationTime"></param>
        /// <param name="chainIndex"></param>
        /// <param name="inputHash"></param>
        /// <param name="aggregationAlgorithmId"></param>
        /// <param name="chainLinks"></param>
        public AggregationHashChain(ulong aggreationTime, ulong[] chainIndex, DataHash inputHash, ulong aggregationAlgorithmId, Link[] chainLinks)
            : base(Constants.AggregationHashChain.TagType, false, false, BuildChildTags(aggreationTime, chainIndex, inputHash, aggregationAlgorithmId, chainLinks))
        {
        }

        /// <summary>
        ///     Create new aggregation hash chain TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationHashChain(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationHashChain.AggregationTimeTagType:
                    return _aggregationTime = GetIntegerTag(childTag);
                case Constants.AggregationHashChain.ChainIndexTagType:
                    IntegerTag chainIndexTag = GetIntegerTag(childTag);
                    _chainIndex.Add(chainIndexTag);
                    return chainIndexTag;
                case Constants.AggregationHashChain.InputDataTagType:
                    return _inputData = GetRawTag(childTag);
                case Constants.AggregationHashChain.InputHashTagType:
                    return _inputHash = GetImprintTag(childTag);
                case Constants.AggregationHashChain.AggregationAlgorithmIdTagType:
                    return _aggrAlgorithmId = GetIntegerTag(childTag);
                case (uint)LinkDirection.Left:
                case (uint)LinkDirection.Right:
                    Link linkTag = childTag as Link ?? new Link(childTag);
                    _links.Add(linkTag);
                    return linkTag;
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

            if (tagCounter[Constants.AggregationHashChain.AggregationTimeTagType] != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in aggregation hash chain.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain index is missing in aggregation hash chain.");
            }

            if (tagCounter[Constants.AggregationHashChain.InputDataTagType] > 1)
            {
                throw new TlvException("Only one input data value is allowed in aggregation hash chain.");
            }

            if (tagCounter[Constants.AggregationHashChain.InputHashTagType] != 1)
            {
                throw new TlvException("Exactly one input hash must exist in aggregation hash chain.");
            }

            if (tagCounter[Constants.AggregationHashChain.AggregationAlgorithmIdTagType] != 1)
            {
                throw new TlvException("Exactly one algorithm must exist in aggregation hash chain.");
            }

            if (_links.Count == 0)
            {
                throw new TlvException("Links are missing in aggregation hash chain.");
            }
        }

        /// <summary>
        /// Create child TLV element list
        /// </summary>
        /// <param name="aggreationTime"></param>
        /// <param name="chainIndex"></param>
        /// <param name="inputHash"></param>
        /// <param name="aggregationAlgorithmId"></param>
        /// <param name="chainLinks"></param>
        /// <returns></returns>
        private static ITlvTag[] BuildChildTags(ulong aggreationTime, ulong[] chainIndex, DataHash inputHash, ulong aggregationAlgorithmId,
                                                Link[] chainLinks)
        {
            if (chainIndex == null)
            {
                throw new ArgumentNullException(nameof(chainIndex));
            }

            if (chainLinks == null)
            {
                throw new ArgumentNullException(nameof(chainLinks));
            }

            List<ITlvTag> list = new List<ITlvTag>(new ITlvTag[]
            {
                new IntegerTag(Constants.AggregationHashChain.AggregationTimeTagType, false, false, aggreationTime),
            });

            foreach (ulong index in chainIndex)
            {
                list.Add(new IntegerTag(Constants.AggregationHashChain.ChainIndexTagType, false, false, index));
            }

            list.Add(new ImprintTag(Constants.AggregationHashChain.InputHashTagType, false, false, inputHash));
            list.Add(new IntegerTag(Constants.AggregationHashChain.AggregationAlgorithmIdTagType, false, false, aggregationAlgorithmId));

            foreach (Link link in chainLinks)
            {
                list.Add(link);
            }

            return list.ToArray();
        }

        /// <summary>
        ///     Get hash chain input hash.
        /// </summary>
        public DataHash InputHash => _inputHash.Value;

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationTime.Value;

        /// <summary>
        /// Get chain index values
        /// </summary>
        /// <returns></returns>
        public ulong[] GetChainIndex()
        {
            List<ulong> result = new List<ulong>();
            foreach (IntegerTag tag in _chainIndex)
            {
                result.Add(tag.Value);
            }
            return result.ToArray();
        }

        /// <summary>
        /// Get aggregation chain links
        /// </summary>
        /// <returns></returns>
        public ReadOnlyCollection<Link> GetChainLinks()
        {
            return _links.AsReadOnly();
        }

        /// <summary>
        ///     Get input data bytes if input data exists otherwise null.
        /// </summary>
        /// <returns>input data bytes</returns>
        public byte[] GetInputData()
        {
            return _inputData?.Value;
        }

        /// <summary>
        /// Returns location pointer based on aggregation hash chain links
        /// </summary>
        /// <returns></returns>
        public ulong CalcLocationPointer()
        {
            return CalcLocationPointer(_links.ToArray());
        }

        /// <summary>
        /// eturns location pointer based on aggregation hash chain links
        /// </summary>
        /// <param name="links">aggregation hash chain links</param>
        /// <returns></returns>
        public static ulong CalcLocationPointer(Link[] links)
        {
            ulong result = 0;

            for (int i = 0; i < links.Length; i++)
            {
                if (links[i].Direction == LinkDirection.Left)
                {
                    result |= 1UL << i;
                }
            }

            result |= 1UL << links.Length;

            return result;
        }

        /// <summary>
        /// Get the (partial) signer identity from the current hash chain.
        /// </summary>
        /// <returns></returns>
        [Obsolete("This method is obsolete. Use GetIdentity() method instead.", false)]
        public string GetChainIdentity()
        {
            string identity = "";

            foreach (IIdentity linkIdentity in GetIdentity())
            {
                string id = linkIdentity.ClientId;
                if (id.Length <= 0)
                {
                    continue;
                }

                if (identity.Length > 0)
                {
                    identity += " :: ";
                }

                identity += id;
            }

            return identity;
        }

        /// <summary>
        /// Returns list of chain link identities
        /// </summary>
        /// <returns></returns>
        public IEnumerable<IIdentity> GetIdentity()
        {
            for (int i = _links.Count - 1; i >= 0; i--)
            {
                Link aggregationChainLink = _links[i];
                IIdentity linkIdentity = aggregationChainLink.GetIdentity();
                if (linkIdentity != null)
                {
                    yield return linkIdentity;
                }
            }
        }

        /// <summary>
        ///     Get output hash.
        /// </summary>
        /// <param name="result">last hashing result</param>
        /// <returns>output hash chain result</returns>
        public AggregationHashChainResult GetOutputHash(AggregationHashChainResult result)
        {
            if (result == null)
            {
                throw new KsiException("Invalid aggregation chain result: null.");
            }

            if (_aggregationHashChainResultCache == null)
            {
                _aggregationHashChainResultCache = new Dictionary<AggregationHashChainResult, AggregationHashChainResult>();
            }
            else if (_aggregationHashChainResultCache.ContainsKey(result))
            {
                return _aggregationHashChainResultCache[result];
            }

            DataHash lastHash = result.Hash;
            ulong level = result.Level;

            foreach (Link link in _links)
            {
                level += link.LevelCorrection + 1;

                if (link.Direction == LinkDirection.Left)
                {
                    lastHash = GetStepHash(lastHash.Imprint, link.GetSiblingData(), level);
                }
                if (link.Direction == LinkDirection.Right)
                {
                    lastHash = GetStepHash(link.GetSiblingData(), lastHash.Imprint, level);
                }
            }

            AggregationHashChainResult returnValue = new AggregationHashChainResult(level, lastHash);
            _aggregationHashChainResultCache[result] = returnValue;

            return returnValue;
        }

        /// <summary>
        ///     Hash two hashes together.
        /// </summary>
        /// <param name="hashA">first hash</param>
        /// <param name="hashB">second hash</param>
        /// <param name="level">hash chain level</param>
        /// <returns>resulting hash</returns>
        private DataHash GetStepHash(byte[] hashA, byte[] hashB, ulong level)
        {
            IDataHasher hasher = KsiProvider.CreateDataHasher(HashAlgorithm.GetById((byte)_aggrAlgorithmId.Value));
            hasher.AddData(hashA);
            hasher.AddData(hashB);
            hasher.AddData(Util.EncodeUnsignedLong(level));
            return hasher.GetHash();
        }

        /// <summary>
        ///     Aggregation hash chain chain index ordering. Orders by chain index length descending.
        /// </summary>
        internal class ChainIndexOrdering : IComparer<AggregationHashChain>
        {
            /// <summary>
            ///     Compare aggregation hash chains to eachother.
            /// </summary>
            /// <param name="x">aggregation hash chain</param>
            /// <param name="y">aggregation hash chain</param>
            /// <returns>0 if equal, 1 if x is shorter, -1 if y is shorter</returns>
            public int Compare(AggregationHashChain x, AggregationHashChain y)
            {
                return y._chainIndex.Count.CompareTo(x._chainIndex.Count);
            }
        }
    }
}