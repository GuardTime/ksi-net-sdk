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
        private readonly IntegerTag _aggrAlgorithmId;
        private readonly IntegerTag _aggregationTime;
        private readonly List<Link> _links = new List<Link>();
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private readonly RawTag _inputData;
        private readonly ImprintTag _inputHash;
        private Dictionary<AggregationHashChainResult, AggregationHashChainResult> _aggregationHashChainResultCache;

        /// <summary>
        ///  Create new aggregation hash chain TLV element from TLV element.
        /// </summary>
        /// <param name="aggreationTime"></param>
        /// <param name="chainIndex"></param>
        /// <param name="inputHash"></param>
        /// <param name="aggregationAlgorithmId"></param>
        /// <param name="chainLinks"></param>
        public AggregationHashChain(ulong aggreationTime, ulong[] chainIndex, DataHash inputHash, ulong aggregationAlgorithmId, Link[] chainLinks)
            : this(new AggregationHashChain(BuildChildTags(aggreationTime, chainIndex, inputHash, aggregationAlgorithmId, chainLinks)))
        {
        }

        /// <summary>
        ///     Create new aggregation hash chain TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationHashChain(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationHashChain.TagType)
            {
                throw new TlvException("Invalid aggregation hash chain type(" + Type + ").");
            }

            int aggregationTimeCount = 0;
            int inputDataCount = 0;
            int inputHashCount = 0;
            int aggrAlgorithmIdCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationHashChain.AggregationTimeTagType:
                        this[i] = _aggregationTime = new IntegerTag(childTag);
                        aggregationTimeCount++;
                        break;
                    case Constants.AggregationHashChain.ChainIndexTagType:
                        IntegerTag chainIndexTag = new IntegerTag(childTag);
                        _chainIndex.Add(chainIndexTag);
                        this[i] = chainIndexTag;
                        break;
                    case Constants.AggregationHashChain.InputDataTagType:
                        this[i] = _inputData = new RawTag(childTag);
                        inputDataCount++;
                        break;
                    case Constants.AggregationHashChain.InputHashTagType:
                        this[i] = _inputHash = new ImprintTag(childTag);
                        inputHashCount++;
                        break;
                    case Constants.AggregationHashChain.AggregationAlgorithmIdTagType:
                        this[i] = _aggrAlgorithmId = new IntegerTag(childTag);
                        aggrAlgorithmIdCount++;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link linkTag = new Link(childTag, (LinkDirection)childTag.Type);
                        _links.Add(linkTag);
                        this[i] = linkTag;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in aggregation hash chain.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain index is missing in aggregation hash chain.");
            }

            if (inputDataCount > 1)
            {
                throw new TlvException("Only one input data value is allowed in aggregation hash chain.");
            }

            if (inputHashCount != 1)
            {
                throw new TlvException("Exactly one input hash must exist in aggregation hash chain.");
            }

            if (aggrAlgorithmIdCount != 1)
            {
                throw new TlvException("Exactly one algorithm must exist in aggregation hash chain.");
            }

            if (_links.Count == 0)
            {
                throw new TlvException("Links are missing in aggregation hash chain.");
            }
        }

        /// <summary>
        /// Create new aggregation hash chain TLV element from child TLV elements.
        /// </summary>
        /// <param name="childTags">Child TLV elements</param>
        private AggregationHashChain(ITlvTag[] childTags) : base(Constants.AggregationHashChain.TagType, false, false, childTags)
        {
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
                new ImprintTag(Constants.AggregationHashChain.InputHashTagType, false, false, inputHash),
                new IntegerTag(Constants.AggregationHashChain.AggregationAlgorithmIdTagType, false, false, aggregationAlgorithmId),
            });

            foreach (ulong index in chainIndex)
            {
                list.Add(new IntegerTag(Constants.AggregationHashChain.ChainIndexTagType, false, false, index));
            }

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
        public string GetChainIdentity()
        {
            string identity = "";

            foreach (Link aggregationChainLink in _links)
            {
                string id = aggregationChainLink.GetIdentity();
                if (id.Length <= 0)
                {
                    continue;
                }
                if (identity.Length > 0)
                {
                    identity = " :: " + identity;
                }
                identity = id + identity;
            }
            return identity;
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
            _aggregationHashChainResultCache.Add(result, returnValue);

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
        ///     Aggregation hash chain chain index ordering.
        /// </summary>
        internal class ChainIndexOrdering : IComparer<AggregationHashChain>
        {
            /// <summary>
            ///     Compare aggregation hash chains to eachother.
            /// </summary>
            /// <param name="x">aggregation hash chain</param>
            /// <param name="y">aggregation hash chain</param>
            /// <returns>0 if equal, 1 if bigger, -1 if smaller</returns>
            public int Compare(AggregationHashChain x, AggregationHashChain y)
            {
                for (int i = 0; i < x._chainIndex.Count; i++)
                {
                    if (i >= y._chainIndex.Count)
                    {
                        return -1;
                    }

                    if (x._chainIndex[i].Value != y._chainIndex[i].Value)
                    {
                        throw new KsiException("Chain index mismatch.");
                    }
                }

                return x._chainIndex.Count == y._chainIndex.Count ? 0 : 1;
            }
        }
    }
}