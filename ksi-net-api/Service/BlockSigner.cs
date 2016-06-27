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
    /// Class to create multiple uni-signatures or one multi-signature.
    /// </summary>
    public class BlockSigner
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly List<TreeNode> _documentNodes;
        private readonly Ksi _ksi;

        private IKsiSignature _rootSignature;
        private TreeNode _root;
        private bool _canAddItems = true;
        private bool _isTreeBuilt;
        private readonly bool _useBlindingMasks;
        private readonly byte[] _randomSeed;
        private readonly HashAlgorithm _hashAlgorithm;

        /// <summary>
        /// Create new block signer instance
        /// </summary>
        /// <param name="ksi">KSI instance</param>
        /// <param name="hashAlgorithm">Hash algorithm to be used when creating aggregation hash chains. If null then defult is used.</param>
        public BlockSigner(Ksi ksi, HashAlgorithm hashAlgorithm = null)
        {
            if (ksi == null)
            {
                throw new ArgumentNullException(nameof(ksi));
            }

            _hashAlgorithm = hashAlgorithm ?? HashAlgorithm.Default;

            _ksi = ksi;
            _documentNodes = new List<TreeNode>();
        }

        /// <summary>
        ///  Create new block signer instance
        /// </summary>
        /// <param name="ksi">KSI instance</param>
        /// <param name="useBlindingMask">If true then blinding masks are used when aggregating</param>
        /// <param name="randomSeed">Random seed for for blinding masks</param>
        /// <param name="hashAlgorithm">Hash algorithm to be used when creating aggregation hash chains. If null then defult is used.</param>
        public BlockSigner(Ksi ksi, bool useBlindingMask, byte[] randomSeed, HashAlgorithm hashAlgorithm = null) : this(ksi, hashAlgorithm)
        {
            _useBlindingMasks = useBlindingMask;
            if (_useBlindingMasks && randomSeed == null)
            {
                throw new BlockSigningException("Random seed cannot be null when using blinding masks.");
            }
            _randomSeed = randomSeed;
        }

        /// <summary>
        /// Add an item to be signed
        /// </summary>
        /// <param name="documentHash"></param>
        /// <param name="metadata"></param>
        public void AddDocument(DataHash documentHash, AggregationHashChain.Metadata metadata = null)
        {
            if (!_canAddItems)
            {
                throw new BlockSigningException("Signing process is started. Cannot add new items.");
            }

            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            _documentNodes.Add(new TreeNode(documentHash, metadata));
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
        /// Get Merkle tree string representation
        /// </summary>
        /// <returns></returns>
        public TreeNode GetRootNode()
        {
            BuildTree();
            return _root;
        }

        /// <summary>
        /// Sign tree root hash.
        /// </summary>
        private void SignRoot()
        {
            _canAddItems = false;
            Logger.Debug("Creating tree.");
            BuildTree();
            uint signLevel = _root.Level;

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
            Logger.Debug("Start creating uni-signatures.");

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

                    Array.Copy(stream.ToArray(), signatureData, stream.Length);
                    Array.Copy(rootSignatureData, 0, signatureData, stream.Length, rootSignatureData.Length);

                    // Create new signature from the signature data.
                    yield return new RawTag(Constants.KsiSignature.TagType, false, false, signatureData);
                }
            }

            Logger.Debug("End creating uni-signatures.");
        }

        /// <summary>
        /// Create multi-signature.
        /// </summary>
        /// <param name="existingAggregationHashChain"></param>
        /// <returns></returns>
        private KsiMultiSignature CreateMultiSignature(AggregationHashChain existingAggregationHashChain)
        {
            Logger.Debug("Start creating multi-signature.");

            ulong[] chainIndex = PrepareChainIndex(existingAggregationHashChain);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());
            multiSignature.Add(_rootSignature);

            foreach (TreeNode node in _documentNodes)
            {
                AggregationHashChain aggregationHashChain = GetAggregationHashChain(existingAggregationHashChain, node, chainIndex);
                multiSignature.Add(aggregationHashChain);
            }

            Logger.Debug("End creating multi-signature.");

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
        private AggregationHashChain GetAggregationHashChain(AggregationHashChain existingChain, TreeNode node, ulong[] chainIndex)
        {
            AggregationHashChain.Link[] chainLinks = CreateAggregationHashChainLinks(node);
            chainIndex[chainIndex.Length - 1] = AggregationHashChain.CalcLocationPointer(chainLinks);

            return new AggregationHashChain(existingChain.AggregationTime, chainIndex, node.DocumentHash, _hashAlgorithm.Id, chainLinks);
        }

        /// <summary>
        /// Creates aggregation hash chain links for given tree node
        /// </summary>
        /// <param name="node">Leaf node</param>
        /// <returns></returns>
        private static AggregationHashChain.Link[] CreateAggregationHashChainLinks(TreeNode node)
        {
            List<AggregationHashChain.Link> links = new List<AggregationHashChain.Link>();

            while (node.Parent != null)
            {
                uint levelCorrection = node.Parent.Level - node.Level - 1;
                if (node.IsLeftNode)
                {
                    links.Add(new AggregationHashChain.Link(
                        LinkDirection.Left,
                        node.Parent.Right.NodeHash,
                        node.Parent.Right.NodeHash == null ? node.Parent.Right.Metadata : null,
                        levelCorrection));
                }
                else
                {
                    links.Add(new AggregationHashChain.Link(
                        LinkDirection.Right,
                        node.Parent.Left.NodeHash,
                        node.Parent.Left.NodeHash == null ? node.Parent.Left.Metadata : null,
                        levelCorrection));
                }

                node = node.Parent;
            }

            return links.ToArray();
        }

        /// <summary>
        /// Builds Merkle tree and returns root node
        /// </summary>
        /// <param name="documentNodes"></param>
        /// <returns></returns>
        private TreeNode GetTreeRoot(List<TreeNode> documentNodes)
        {
            List<TreeNode> treeNodes = new List<TreeNode>();

            for (int i = 0; i < documentNodes.Count; i++)
            {
                TreeNode node = documentNodes[i];

                AggregationHashChain.Metadata metadata = node.Metadata;

                if (metadata != null)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher(_hashAlgorithm);
                    hasher.AddData(node.DocumentHash.Imprint);
                    hasher.AddData(metadata.EncodeValue());
                    hasher.AddData(Util.EncodeUnsignedLong(1));

                    TreeNode metadataNode = new TreeNode(metadata);

                    TreeNode parent = new TreeNode(1)
                    {
                        NodeHash = hasher.GetHash(),
                        Left = node,
                        Right = metadataNode
                    };

                    node.IsLeftNode = true;
                    metadataNode.IsLeftNode = false;

                    node.Parent = metadataNode.Parent = parent;

                    treeNodes.Add(parent);
                }
                else
                {
                    treeNodes.Add(node);
                }
            }

            if (_useBlindingMasks)
            {
                AddBlindingMasks(treeNodes);
            }

            return MakeTree(treeNodes, 2);
        }

        /// <summary>
        /// Add blinding masks as Merkle tree leaves
        /// </summary>
        /// <param name="treeNodes"></param>
        private void AddBlindingMasks(List<TreeNode> treeNodes)
        {
            byte[] previousHash = new byte[_hashAlgorithm.Length + 1];

            for (int i = 0; i < treeNodes.Count;)
            {
                TreeNode node = treeNodes[i];

                IDataHasher hasher = KsiProvider.CreateDataHasher(_hashAlgorithm);
                hasher.AddData(previousHash);
                hasher.AddData(_randomSeed);

                TreeNode maskNode = new TreeNode(hasher.GetHash());
                treeNodes.Insert(i, maskNode);
                previousHash = node.NodeHash.Imprint;
                i += 2;
            }
        }

        /// <summary>
        /// Builds Merkle tree
        /// </summary>
        /// <param name="nodes">Leaf nodes</param>
        /// <param name="parentLevel">Level for parent node</param>
        /// <returns>Root node</returns>
        private TreeNode MakeTree(IList<TreeNode> nodes, uint parentLevel)
        {
            List<TreeNode> list = new List<TreeNode>(nodes);
            List<TreeNode> nextLevelList = new List<TreeNode>();
            uint level = parentLevel;

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

                    IDataHasher hasher = KsiProvider.CreateDataHasher(_hashAlgorithm);
                    hasher.AddData(leftNode.NodeHash.Imprint);
                    hasher.AddData(rightNode.NodeHash.Imprint);
                    hasher.AddData(Util.EncodeUnsignedLong(level));
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