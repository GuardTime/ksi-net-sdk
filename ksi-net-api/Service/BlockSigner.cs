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
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class to create multiple uni-signatures.
    /// </summary>
    public class BlockSigner
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly IKsiService _ksiService;
        private const uint MaxLevel = 255;

        private TreeNode _root;
        private bool _canAddItems = true;
        private bool _isTreeBuilt;
        private readonly bool _useBlindingMasks;
        private readonly byte[] _randomSeed;
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly IKsiSignatureFactory _signatureFactory;

        /// <summary>
        /// Merkle tree root hash signature
        /// </summary>
        protected IKsiSignature RootSignature;

        /// <summary>
        /// List of nodes containing document hashes
        /// </summary>
        protected readonly List<TreeNode> DocumentNodes = new List<TreeNode>();

        /// <summary>
        /// Create new block signer instance
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        /// <param name="hashAlgorithm">Hash algorithm to be used when creating aggregation hash chains. If null then defult is used.</param>
        /// <param name="signatureFactory">Signature factory for creating uni-signatures.</param>
        public BlockSigner(IKsiService ksiService, HashAlgorithm hashAlgorithm = null, IKsiSignatureFactory signatureFactory = null)
        {
            if (ksiService == null)
            {
                throw new ArgumentNullException(nameof(ksiService));
            }

            _hashAlgorithm = hashAlgorithm ?? HashAlgorithm.Default;
            _ksiService = ksiService;

            _signatureFactory = signatureFactory ?? new KsiSignatureFactory();
        }

        /// <summary>
        ///  Create new block signer instance
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        /// <param name="useBlindingMask">If true then blinding masks are used when aggregating</param>
        /// <param name="randomSeed">Random seed for for blinding masks</param>
        /// <param name="hashAlgorithm">Hash algorithm to be used when creating aggregation hash chains. If null then defult is used.</param>
        /// <param name="signatureFactory">KSI signature factory for creating uni-signatures.</param>
        public BlockSigner(IKsiService ksiService, bool useBlindingMask, byte[] randomSeed, HashAlgorithm hashAlgorithm = null, IKsiSignatureFactory signatureFactory = null)
            : this(ksiService, hashAlgorithm, signatureFactory)
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
        /// <param name="documentHash">Document hash</param>
        /// <param name="metadata">Metadata to be added together with document hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        public void AddDocument(DataHash documentHash, AggregationHashChain.Metadata metadata = null, uint? level = null)
        {
            if (!_canAddItems)
            {
                throw new BlockSigningException("Signing process is started. Cannot add new items.");
            }

            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            if (level.HasValue && (level < 0 || level > MaxLevel))
            {
                throw new ArgumentOutOfRangeException(nameof(level), "Level must be between 0 and 255");
            }

            DocumentNodes.Add(new TreeNode(documentHash, metadata, level));
        }

        /// <summary>
        /// Sign given hashes. Returns uni-signatures.
        /// </summary>
        public IEnumerable<IKsiSignature> GetUniSignatures()
        {
            if (DocumentNodes.Count == 0)
            {
                return new List<IKsiSignature>();
            }

            SignRoot();
            AggregationHashChain existingAggregationHashChain = RootSignature.GetAggregationHashChains()[0];
            return CreateUniSignatures(existingAggregationHashChain);
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

            Logger.Debug("Signing root node hash. Level: {0}; Hash: {1}", signLevel, _root.NodeHash);

            RequestResponsePayload signResponsePayload = _ksiService.GetSignResponsePayload(_ksiService.BeginSign(_root.NodeHash, signLevel, null, null));

            RootSignature = new KsiSignature(false, false, signResponsePayload.GetSignatureChildTags());
        }

        /// <summary>
        /// Build Merkle tree.
        /// </summary>
        private void BuildTree()
        {
            if (DocumentNodes.Count == 0)
            {
                return;
            }

            if (!_isTreeBuilt)
            {
                _root = GetTreeRoot(DocumentNodes);
                _isTreeBuilt = true;
            }
        }

        /// <summary>
        /// Create uni-signatures based on the root signature.
        /// </summary>
        /// <param name="existingAggregationHashChain"></param>
        /// <returns></returns>
        private IEnumerable<IKsiSignature> CreateUniSignatures(AggregationHashChain existingAggregationHashChain)
        {
            Logger.Debug("Start creating uni-signatures.");

            byte[] rootSignatureData = RootSignature.EncodeValue();
            ulong[] chainIndex = PrepareChainIndex(existingAggregationHashChain);

            foreach (TreeNode node in DocumentNodes)
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
                    yield return _signatureFactory.CreateByContent(signatureData, node.NodeHash);
                }
            }

            Logger.Debug("End creating uni-signatures.");
        }

        /// <summary>
        /// Prepare chain index. Leave element is filled later.
        /// </summary>
        /// <param name="existingChain"></param>
        /// <returns></returns>
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
            bool isFirstNode = true;

            while (node.Parent != null)
            {
                uint levelCorrection = node.Parent.Level - node.Level - 1;
                if (isFirstNode)
                {
                    levelCorrection += node.Level;
                    isFirstNode = false;
                }

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
                    hasher.AddData(Util.EncodeUnsignedLong(node.Level + 1));

                    TreeNode metadataNode = new TreeNode(metadata, node.Level);

                    TreeNode parent = new TreeNode(node.Level + 1)
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

            return MakeTree(treeNodes);
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

                TreeNode maskNode = new TreeNode(hasher.GetHash(), null, node.Level);
                treeNodes.Insert(i, maskNode);
                previousHash = node.NodeHash.Imprint;
                i += 2;
            }
        }

        /// <summary>
        /// Builds Merkle tree
        /// </summary>
        /// <param name="nodes">Leaf nodes</param>
        /// <returns>Root node</returns>
        private TreeNode MakeTree(IList<TreeNode> nodes)
        {
            List<TreeNode> list = new List<TreeNode>(nodes);
            List<TreeNode> nextLevelList = new List<TreeNode>();

            while (list.Count > 1)
            {
                for (int i = 0; i + 1 < list.Count; i += 2)
                {
                    TreeNode leftNode = list[i];
                    TreeNode rightNode = list[i + 1];
                    uint level = Math.Max(leftNode.Level, rightNode.Level) + 1;

                    TreeNode treeNode = new TreeNode(level);

                    leftNode.Parent = treeNode;
                    leftNode.IsLeftNode = true;

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
            }

            return list[0];
        }
    }
}