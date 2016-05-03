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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.MultiSignature;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class to do create multiple signatures or multi-signature.
    /// </summary>
    public partial class BlockSigner
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly List<TreeNode> _documentNodes;
        private readonly Ksi _ksi;

        private IKsiSignature _rootSignature;
        private TreeNode _root;
        private bool _canAddItems = true;
        private bool _isTreeBuilt;

        /// <summary>
        /// Create new signer instance
        /// </summary>
        /// <param name="ksi">KSI instance</param>
        public BlockSigner(Ksi ksi)
        {
            if (ksi == null)
            {
                throw new ArgumentNullException(nameof(ksi));
            }

            _ksi = ksi;
            _documentNodes = new List<TreeNode>();
        }

        /// <summary>
        /// Add an item to be signed
        /// </summary>
        /// <param name="documentHash"></param>
        /// <param name="metaData"></param>
        public void AddDocument(DataHash documentHash, AggregationHashChain.MetaData metaData)
        {
            if (!_canAddItems)
            {
                throw new BlockSigningException("Signing process is started. Cannot add new items.");
            }

            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            if (metaData == null)
            {
                throw new ArgumentNullException(nameof(metaData));
            }

            _documentNodes.Add(new TreeNode(documentHash, metaData));
        }

        /// <summary>
        /// Sign given hashes. Returns uni-signatures.
        /// </summary>
        public IEnumerable<RawTag> GetUniSignatures()
        {
            if (_documentNodes.Count == 0)
            {
                return new List<RawTag>();
            }

            SignRoot();
            AggregationHashChain existingAggregationHashChain = _rootSignature.GetAggregationHashChains()[0];
            return CreateUniSignatures(existingAggregationHashChain);
        }

        /// <summary>
        /// Sign given hashes. Returns multi-signature
        /// </summary>
        public KsiMultiSignature GetMultiSignature()
        {
            if (_documentNodes.Count == 0)
            {
                return new KsiMultiSignature(new KsiSignatureFactory());
            }

            SignRoot();
            AggregationHashChain existingAggregationHashChain = _rootSignature.GetAggregationHashChains()[0];
            return CreateMultiSignature(existingAggregationHashChain);
        }

        /// <summary>
        /// Sign tree root hash.
        /// </summary>
        private void SignRoot()
        {
            _canAddItems = false;
            Logger.Debug("Creating tree.");
            BuildTree();
            uint signLevel = _root.Level + 1;

            Logger.Debug("Signing root node hash. Level: {0}; Hash: ", signLevel, _root.NodeHash);
            _rootSignature = _ksi.Sign(_root.NodeHash, signLevel);
        }

        /// <summary>
        /// Build Merkle tree.
        /// </summary>
        private void BuildTree()
        {
            if (_documentNodes.Count == 0)
            {
                return;
            }

            if (!_isTreeBuilt)
            {
                _root = GetTreeRoot(_documentNodes);
                _isTreeBuilt = true;
            }
        }

        /// <summary>
        /// Create uni-signatures based on the root signature.
        /// </summary>
        /// <param name="existingAggregationHashChain"></param>
        /// <returns></returns>
        private IEnumerable<RawTag> CreateUniSignatures(AggregationHashChain existingAggregationHashChain)
        {
            Logger.Debug("Start creating signatures.");

            byte[] rootSignatureData = _rootSignature.EncodeValue();
            ulong[] chainIndex = PrepareChainIndex(existingAggregationHashChain);

            foreach (TreeNode node in _documentNodes)
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    AggregationHashChain aggregationHashChain = GetAggregationHashChain(existingAggregationHashChain, node, chainIndex);
                    aggregationHashChain.WriteTo(stream);

                    // Take root node signature data and add aggregation hash chain.
                    byte[] signatureData = new byte[rootSignatureData.Length + stream.Length];
                    Array.Copy(rootSignatureData, signatureData, rootSignatureData.Length);
                    Array.Copy(stream.ToArray(), 0, signatureData, rootSignatureData.Length, stream.Length);

                    // Create new signature from the signature data.
                    yield return new RawTag(Constants.KsiSignature.TagType, false, false, signatureData);
                }
            }

            Logger.Debug("End creating signatures.");
        }

        /// <summary>
        /// Create multi-signature.
        /// </summary>
        /// <param name="existingAggregationHashChain"></param>
        /// <returns></returns>
        private KsiMultiSignature CreateMultiSignature(AggregationHashChain existingAggregationHashChain)
        {
            Logger.Debug("Start creating multi signature.");

            ulong[] chainIndex = PrepareChainIndex(existingAggregationHashChain);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());
            multiSignature.Add(_rootSignature);

            foreach (TreeNode node in _documentNodes)
            {
                AggregationHashChain aggregationHashChain = GetAggregationHashChain(existingAggregationHashChain, node, chainIndex);
                multiSignature.Add(aggregationHashChain);
            }

            Logger.Debug("End creating multi signature.");

            return multiSignature;
        }

        private static ulong[] PrepareChainIndex(AggregationHashChain existingChain)
        {
            ulong[] existingChainIndex = existingChain.GetChainIndex();
            ulong[] chainIndex = new ulong[existingChainIndex.Length + 1];
            Array.Copy(existingChainIndex, chainIndex, existingChainIndex.Length);
            return chainIndex;
        }

        /// <summary>
        /// Get new aggregation hash chain based on the root signature aggregation hash chain.
        /// </summary>
        /// <param name="existingChain"></param>
        /// <param name="node"></param>
        /// <param name="chainIndex"></param>
        /// <returns></returns>
        private static AggregationHashChain GetAggregationHashChain(AggregationHashChain existingChain, TreeNode node, ulong[] chainIndex)
        {
            AggregationHashChain.Link[] chainLinks = CreateAggregationHashChainLinks(node);
            chainIndex[chainIndex.Length - 1] = AggregationHashChain.CalcLocationPointer(chainLinks);

            return new AggregationHashChain(existingChain.AggregationTime, chainIndex, node.DocumentHash,
                node.DocumentHash.Algorithm.Id, chainLinks);
        }

        /// <summary>
        /// Get Merkle tree string representation
        /// </summary>
        /// <returns></returns>
        public string PrintTree()
        {
            BuildTree();
            return TreeNode.PrintTree(_documentNodes);
        }

        /// <summary>
        /// Creates aggregation hash chain links for given tree node
        /// </summary>
        /// <param name="node">Leaf node</param>
        /// <returns></returns>
        private static AggregationHashChain.Link[] CreateAggregationHashChainLinks(TreeNode node)
        {
            List<AggregationHashChain.Link> links = new List<AggregationHashChain.Link> { new AggregationHashChain.Link(LinkDirection.Left, null, node.MetaData, 0) };

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
        private static TreeNode GetTreeRoot(List<TreeNode> documentNodes)
        {
            foreach (TreeNode treeNode in documentNodes)
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
        private static DataHash GetLeafHash(TreeNode node)
        {
            IDataHasher hasher = KsiProvider.CreateDataHasher();
            hasher.AddData(node.DocumentHash.Imprint);
            hasher.AddData(node.MetaData.EncodeValue());
            hasher.AddData(Util.EncodeUnsignedLong(1));
            return hasher.GetHash();
        }

        /// <summary>
        /// Builds Merkle tree
        /// </summary>
        /// <param name="nodes">Leaf nodes</param>
        /// <returns>Root node</returns>
        private static TreeNode MakeTree(IList<TreeNode> nodes)
        {
            List<TreeNode> list = new List<TreeNode>(nodes);
            List<TreeNode> nextLevelList = new List<TreeNode>();
            uint level = 1;

            while (list.Count > 1)
            {
                for (int i = 0; i + 1 < list.Count; i += 2)
                {
                    TreeNode treeNode = new TreeNode(level);

                    TreeNode leftNode = list[i];
                    leftNode.Parent = treeNode;
                    leftNode.IsLeftNode = true;

                    TreeNode rightNode = list[i + 1];
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
                nextLevelList = new List<TreeNode>();
                level++;
            }

            return list[0];
        }
    }
}