/*
 * Copyright 2013-2018 Guardtime, Inc.
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
        private bool _canAddItems = true;
        private readonly bool _useBlindingMasks;
        private readonly byte[] _randomSeed;
        private byte[] _previousHash;
        private readonly HashAlgorithm _hashAlgorithm;
        private IDataHasher _dataHasher;
        private readonly IKsiSignatureFactory _signatureFactory;
        private readonly List<TreeNode> _leafNodes = new List<TreeNode>();
        readonly TreeBuilder _treeBuilder;

        /// <summary>
        /// Create new block signer instance
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        /// <param name="hashAlgorithm">Hash algorithm to be used when creating aggregation hash chains. If null then defult is used.</param>
        /// <param name="signatureFactory">Signature factory for creating uni-signatures.</param>
        /// <param name="maxTreeHeight">Max allowed aggregation tree height</param>
        public BlockSigner(IKsiService ksiService, HashAlgorithm hashAlgorithm = null, IKsiSignatureFactory signatureFactory = null,
                           uint? maxTreeHeight = null)
        {
            if (ksiService == null)
            {
                throw new ArgumentNullException(nameof(ksiService));
            }

            _hashAlgorithm = hashAlgorithm ?? HashAlgorithm.Default;

            if (_hashAlgorithm.HasDeprecatedSinceDate)
            {
                throw new HashingException(string.Format("Hash algorithm {0} is deprecated since {1} and can not be used.", _hashAlgorithm.Name,
                    _hashAlgorithm.DeprecatedSinceDate?.ToString(Constants.DateFormat)));
            }

            _ksiService = ksiService;
            _signatureFactory = signatureFactory ?? new KsiSignatureFactory();
            _treeBuilder = new TreeBuilder(_hashAlgorithm, maxTreeHeight);
        }

        /// <summary>
        ///  Create new block signer instance
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        /// <param name="useBlindingMasks">If true then blinding masks are used when aggregating</param>
        /// <param name="randomSeed">Random seed for for blinding masks</param>
        /// <param name="hashAlgorithm">Hash algorithm to be used when creating aggregation hash chains. If null then defult is used.</param>
        /// <param name="signatureFactory">KSI signature factory for creating uni-signatures.</param>
        /// <param name="maxTreeHeight">Max allowed aggregation tree height</param>
        public BlockSigner(IKsiService ksiService, bool useBlindingMasks, byte[] randomSeed, HashAlgorithm hashAlgorithm = null, IKsiSignatureFactory signatureFactory = null,
                           uint? maxTreeHeight = null)
            : this(ksiService, hashAlgorithm, signatureFactory, maxTreeHeight)
        {
            if (useBlindingMasks)
            {
                if (randomSeed == null)
                {
                    throw new BlockSigningException("Random seed cannot be null when using blinding masks.");
                }
                _previousHash = new byte[_hashAlgorithm.Length + 1];
                _useBlindingMasks = true;
                _randomSeed = randomSeed;
            }
        }

        private IDataHasher DataHasher
        {
            get
            {
                if (_dataHasher != null)
                {
                    _dataHasher.Reset();
                    return _dataHasher;
                }

                return _dataHasher = KsiProvider.CreateDataHasher(_hashAlgorithm);
            }
        }

        /// <summary>
        /// Add a data hash to be signed. Returns false if the hash cannot be added because tree would get higher than allowed.
        /// </summary>
        /// <param name="dataHash">Data hash to be added</param>
        /// <param name="metadata">Metadata to be added together with data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <returns>false if data hash cannot be added because tree would get higher than allowed, true otherwise.</returns>
        public bool Add(DataHash dataHash, IdentityMetadata metadata = null, uint level = 0)
        {
            if (!_canAddItems)
            {
                throw new BlockSigningException("Signing process is started. Cannot add new items.");
            }

            if (dataHash == null)
            {
                throw new ArgumentNullException(nameof(dataHash));
            }

            TreeNode node = new TreeNode(dataHash, level);

            if (!_treeBuilder.AddNode(node, metadata, _useBlindingMasks ? GetBlindingMaskNode(node) : null))
            {
                return false;
            }

            _leafNodes.Add(node);
            return true;
        }

        /// <summary>
        /// Sign given hashes. Returns uni-signatures.
        /// </summary>
        public IEnumerable<IKsiSignature> Sign()
        {
            _canAddItems = false;

            if (_leafNodes.Count == 0)
            {
                return new List<IKsiSignature>();
            }

            TreeNode root = _treeBuilder.GetTreeRoot();

            if (root.Left == null && root.Right == null)
            {
                Logger.Debug("Only one node in the tree. Signing the hash. Level: {0}; Hash: {1}", root.Level, root.Hash);
                return new List<IKsiSignature>() { _ksiService.Sign(root.Hash, root.Level) };
            }

            Logger.Debug("Signing root node hash. Level: {0}; Hash: {1}", root.Level, root.Hash);
            SignRequestResponsePayload signResponsePayload = _ksiService.GetSignResponsePayload(_ksiService.BeginSign(root.Hash, root.Level, null, null));
            return CreateUniSignatures(new KsiSignature(false, false, signResponsePayload.GetSignatureChildTags()));
        }

        private TreeNode GetBlindingMaskNode(TreeNode node)
        {
            DataHash hash = DataHasher
                .AddData(_previousHash)
                .AddData(_randomSeed)
                .GetHash();

            TreeNode maskNode = new TreeNode(hash, node.Level);
            _previousHash = node.Hash.Imprint;
            return maskNode;
        }

        /// <summary>
        /// Create uni-signatures based on the root signature.
        /// </summary>
        /// <returns></returns>
        private IEnumerable<IKsiSignature> CreateUniSignatures(IKsiSignature rootSignature)
        {
            Logger.Debug("Start creating uni-signatures.");

            AggregationHashChain existingAggregationHashChain = rootSignature.GetAggregationHashChains()[0];
            byte[] rootSignatureData = rootSignature.EncodeValue();
            ulong[] chainIndex = PrepareChainIndex(existingAggregationHashChain);

            foreach (TreeNode node in _leafNodes)
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
                    yield return _signatureFactory.CreateByContent(signatureData, node.Hash);
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

            return new AggregationHashChain(existingChain.AggregationTime, chainIndex, node.Hash, _hashAlgorithm.Id, chainLinks);
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
                    if (node.Parent.Right.Hash == null)
                        links.Add(new AggregationHashChain.Link(
                            LinkDirection.Left,
                            node.Parent.Right.Metadata.AggregationHashChainMetadata,
                            levelCorrection));
                    else
                        links.Add(new AggregationHashChain.Link(
                            LinkDirection.Left,
                            node.Parent.Right.Hash,
                            levelCorrection));
                }
                else
                {
                    if (node.Parent.Left.Hash == null)

                        links.Add(new AggregationHashChain.Link(
                            LinkDirection.Right,
                            node.Parent.Left.Metadata.AggregationHashChainMetadata,
                            levelCorrection));
                    else
                        links.Add(new AggregationHashChain.Link(
                            LinkDirection.Right,
                            node.Parent.Left.Hash,
                            levelCorrection));
                }

                node = node.Parent;
            }

            return links.ToArray();
        }
    }
}