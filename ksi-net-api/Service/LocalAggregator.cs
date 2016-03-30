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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class to do local aggregation.
    /// </summary>
    public partial class LocalAggregator
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly List<AggregationTreeNode> _documentNodes;
        private IKsiSignature _rootSignature;
        private readonly Ksi _ksi;
        private readonly AggregationTreeNode _root;

        /// <summary>
        /// Create local aggregator instance
        /// </summary>
        /// <param name="aggregationItems">Items to be aggregated locally.</param>
        /// <param name="ksi">KSI instance</param>
        public LocalAggregator(LocalAggregationItem[] aggregationItems, Ksi ksi)
        {
            if (aggregationItems == null)
            {
                throw new ArgumentNullException(nameof(aggregationItems));
            }

            if (aggregationItems.Length == 0)
            {
                throw new ArgumentException("List cannot be empty.", nameof(aggregationItems));
            }

            if (ksi == null)
            {
                throw new ArgumentNullException(nameof(ksi));
            }

            _ksi = ksi;

            _documentNodes = new List<AggregationTreeNode>();

            foreach (LocalAggregationItem item in aggregationItems)
            {
                AggregationTreeNode node = new AggregationTreeNode(item);

                _documentNodes.Add(node);
            }

            _root = GetTreeRoot(_documentNodes);
        }

        /// <summary>
        /// Sign given documents
        /// </summary>
        public LocalAggregationItem[] SignDocuments()
        {
            uint signLevel = _root.Level + 1;

            Logger.Debug("Signing root node hash. Level: {0}; Hash: ", signLevel, _root.NodeHash);

            _rootSignature = _ksi.Sign(_root.NodeHash, signLevel);

            AggregationHashChain existingChain = _rootSignature.GetAggregationHashChains()[0];

            ITlvTag[] signatureTags = new ITlvTag[_rootSignature.Count + 1];

            // Copy root node signature tags.
            for (int i = 0; i < _rootSignature.Count; i++)
            {
                signatureTags[i] = _rootSignature[i];
            }

            foreach (AggregationTreeNode node in _documentNodes)
            {
                AggregationHashChain.Link[] chainLinks = CreateAggregationHashChainLinks(node);

                ulong[] existingChainIndex = existingChain.GetChainIndex();
                ulong[] chainIndex = new ulong[existingChainIndex.Length + 1];
                Array.Copy(existingChainIndex, chainIndex, existingChainIndex.Length);
                chainIndex[chainIndex.Length - 1] = AggregationHashChain.Link.GetLocationPointer(chainLinks);

                // Take root node signature tags and add aggregation hash chain.
                signatureTags[_rootSignature.Count] = new AggregationHashChain(existingChain.AggregationTime, chainIndex, node.Item.DocumentHash,
                    node.Item.DocumentHash.Algorithm.Id, chainLinks);

                // Create new signature from the signature tags.
                node.Item.Signature = new KsiSignature(signatureTags);
            }

            LocalAggregationItem[] result = new LocalAggregationItem[_documentNodes.Count];

            for (int i = 0; i < _documentNodes.Count; i++)
            {
                result[i] = _documentNodes[i].Item;
            }

            return result;
        }

        /// <summary>
        /// Get Merkle tree string representation
        /// </summary>
        /// <returns></returns>
        public string PrintTree()
        {
            return AggregationTreeNode.PrintTree(_documentNodes);
        }

        /// <summary>
        /// Creates aggregation hash chain links for given tree node
        /// </summary>
        /// <param name="node">Leaf node</param>
        /// <returns></returns>
        private static AggregationHashChain.Link[] CreateAggregationHashChainLinks(AggregationTreeNode node)
        {
            List<AggregationHashChain.Link> links = new List<AggregationHashChain.Link> { new AggregationHashChain.Link(LinkDirection.Left, null, node.Item.MetaData, 0) };

            while (node.Parent != null)
            {
                links.Add(new AggregationHashChain.Link(
                    node.IsLeftNode ? LinkDirection.Left : LinkDirection.Right,
                    node.IsLeftNode ? node.Parent.Right.NodeHash : node.Parent.Left.NodeHash,
                    null,
                    node.Parent.Level - node.Level - 1));

                node = node.Parent;
            }

            return links.ToArray();
        }

        /// <summary>
        /// Builds Merkle tree and returns root node
        /// </summary>
        /// <param name="documentNodes"></param>
        /// <returns></returns>
        private static AggregationTreeNode GetTreeRoot(List<AggregationTreeNode> documentNodes)
        {
            foreach (AggregationTreeNode treeNode in documentNodes)
            {
                treeNode.NodeHash = GetLeafHash(treeNode);
            }

            return MakeTree(documentNodes);
        }

        /// <summary>
        /// Returns leaf node hash value
        /// </summary>
        /// <param name="node">Leaf node</param>
        /// <returns></returns>
        private static DataHash GetLeafHash(AggregationTreeNode node)
        {
            IDataHasher hasher = KsiProvider.CreateDataHasher();
            hasher.AddData(node.Item.DocumentHash.Imprint);
            hasher.AddData(node.Item.MetaData.EncodeValue());
            hasher.AddData(Util.EncodeUnsignedLong(1));
            return hasher.GetHash();
        }

        /// <summary>
        /// Builds Merkle tree
        /// </summary>
        /// <param name="nodes">Leaf nodes</param>
        /// <returns></returns>
        private static AggregationTreeNode MakeTree(IList<AggregationTreeNode> nodes)
        {
            List<AggregationTreeNode> list = new List<AggregationTreeNode>(nodes);
            List<AggregationTreeNode> nextLevelList = new List<AggregationTreeNode>();
            uint level = 1;

            while (list.Count > 1)
            {
                for (int i = 0; i + 1 < list.Count; i += 2)
                {
                    AggregationTreeNode treeNode = new AggregationTreeNode(level);

                    AggregationTreeNode leftNode = list[i];
                    leftNode.Parent = treeNode;
                    leftNode.IsLeftNode = true;

                    AggregationTreeNode rightNode = list[i + 1];
                    rightNode.Parent = treeNode;
                    rightNode.IsLeftNode = false;

                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    hasher.AddData(leftNode.NodeHash.Imprint);
                    hasher.AddData(rightNode.NodeHash.Imprint);
                    hasher.AddData(Util.EncodeUnsignedLong(level + 1));
                    treeNode.NodeHash = hasher.GetHash();

                    treeNode.Left = leftNode;
                    treeNode.Right = rightNode;

                    nextLevelList.Add(treeNode);
                }

                if (list.Count % 2 == 1)
                {
                    nextLevelList.Add(list[list.Count - 1]);
                }

                list = nextLevelList;
                nextLevelList = new List<AggregationTreeNode>();
                level++;
            }

            return list[0];
        }
    }
}