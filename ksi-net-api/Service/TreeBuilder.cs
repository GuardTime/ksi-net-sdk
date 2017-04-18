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
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class for building Merkle trees.
    /// </summary>
    public class TreeBuilder
    {
        private const uint DefaultMaxTreeHeight = 255;

        /// <summary>
        /// Contains tree root nodes of current forest. Sorted by level descending. No heads have equal levels. 
        /// </summary>
        private readonly List<TreeNode> _heads = new List<TreeNode>();

        IDataHasher _dataHasher;
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly uint _maxTreeHeight;

        /// <summary>
        /// Create new Merkle tree builder instance
        /// </summary>
        /// <param name="maxTreeHeight">Max allowed tree height</param>
        /// <param name="hashAlgorithm">Hash algorithm for creating tree node hashes</param>
        public TreeBuilder(HashAlgorithm hashAlgorithm, uint? maxTreeHeight = null)
        {
            if (maxTreeHeight == null)
            {
                _maxTreeHeight = DefaultMaxTreeHeight;
            }
            else
            {
                if (maxTreeHeight < 0 || maxTreeHeight > DefaultMaxTreeHeight)
                {
                    throw new ArgumentOutOfRangeException(nameof(maxTreeHeight), "Max tree height must be between 0 and " + DefaultMaxTreeHeight);
                }

                _maxTreeHeight = maxTreeHeight.Value;
            }

            _hashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Add node to tree. Returns false if node cannot be added because tree would get higher than allowed.
        /// </summary>
        /// <param name="node">Node to be added</param>
        /// <param name="metadata">Metadata node</param>
        /// <param name="blidnginMaskNode">Blinding mask node</param>
        /// <returns>false if node cannot be added because tree would get higher than allowed, true otherwise.</returns>
        public bool AddNode(TreeNode node, IdentityMetadata metadata = null, TreeNode blidnginMaskNode = null)
        {
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node));
            }

            if (metadata != null)
            {
                node = AddMetadata(node, metadata);
            }

            if (blidnginMaskNode != null)
            {
                node = CreateParentNode(blidnginMaskNode, node);
            }

            if (_heads.Count == 0)
            {
                if (node.Level > _maxTreeHeight)
                {
                    return false;
                }
            }
            else if (CalcNewTreeHeight(node) > _maxTreeHeight)
            {
                return false;
            }

            AddNodeToForest(node, _heads);

            return true;
        }

        /// <summary>
        /// Get tree root node.
        /// </summary>
        /// <returns></returns>
        public TreeNode GetTreeRoot()
        {
            return ExtractLowerHeads(DefaultMaxTreeHeight, _heads);
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

        private TreeNode AddMetadata(TreeNode node, IdentityMetadata metadata)
        {
            DataHash nodeHash = DataHasher
                .AddData(node.Hash.Imprint)
                .AddData(metadata.AggregationHashChainMetadata.EncodeValue())
                .AddData(Util.EncodeUnsignedLong(node.Level + 1))
                .GetHash();

            TreeNode metadataNode = new TreeNode(metadata, node.Level);

            TreeNode parent = new TreeNode(node.Level + 1)
            {
                Hash = nodeHash,
                Left = node,
                Right = metadataNode
            };

            node.IsLeftNode = true;
            metadataNode.IsLeftNode = false;
            node.Parent = metadataNode.Parent = parent;
            node = parent;
            return node;
        }

        /// <summary>
        /// Get calculated tree height after adding the given node.
        /// </summary>
        /// <param name="node">Node to be added</param>
        /// <returns></returns>
        private uint CalcNewTreeHeight(TreeNode node)
        {
            List<TreeNode> heads = CloneHeads();
            // Add cloned node to the cloned heads. Real heads will not be modified.
            AddNodeToForest(new TreeNode(node.Level) { Hash = node.Hash }, heads);
            TreeNode rootNode = ExtractLowerHeads(DefaultMaxTreeHeight, heads);
            return rootNode.Level;
        }

        private List<TreeNode> CloneHeads()
        {
            List<TreeNode> result = new List<TreeNode>();
            foreach (TreeNode node in _heads)
            {
                result.Add(new TreeNode(node.Level) { Hash = node.Hash });
            }
            return result;
        }

        /// <summary>
        /// Add node to forest. 
        /// Lower level heads will be merged.
        /// </summary>
        private void AddNodeToForest(TreeNode node, List<TreeNode> heads)
        {
            if (heads.Count == 0)
            {
                heads.Add(node);
                return;
            }

            TreeNode lowerHeadsRoot = ExtractLowerHeads(node.Level, heads);

            if (lowerHeadsRoot != null)
            {
                if (lowerHeadsRoot.Level > node.Level)
                {
                    heads.Add(node);
                }
                else
                {
                    heads.RemoveAt(heads.Count - 1);
                    AddToHeads(CreateParentNode(lowerHeadsRoot, node), heads);
                }
            }
            else
            {
                AddToHeads(node, heads);
            }
        }

        /// <summary>
        /// Add node to heads. If same level node exists then merge these nodes. 
        /// </summary>
        private void AddToHeads(TreeNode node, List<TreeNode> heads)
        {
            TreeNode sameLevelHead = GetSameLevelNode(node, heads);
            bool removeNodeFromHeads = false;

            if (sameLevelHead == null)
            {
                heads.Add(node);
            }

            while (sameLevelHead != null)
            {
                TreeNode parent = CreateParentNode(sameLevelHead, node);

                if (removeNodeFromHeads)
                {
                    heads.Remove(node);
                }
                else
                {
                    removeNodeFromHeads = true;
                }

                int index = heads.IndexOf(sameLevelHead);
                heads[index] = parent;

                node = parent;
                sameLevelHead = GetSameLevelNode(node, heads);
            }
        }

        /// <summary>
        /// Merge heads that have level lower or equal to the given level.
        /// Merge so that there are no nodes having equal levels.</summary>
        /// Remove merged heads from the list and return root node of the created tree.
        private TreeNode ExtractLowerHeads(uint level, List<TreeNode> heads)
        {
            if (heads.Count == 0)
            {
                return null;
            }

            TreeNode last = heads[heads.Count - 1];

            if (last.Level > level)
            {
                return null;
            }

            while (heads.Count > 1)
            {
                TreeNode penultimate = heads[heads.Count - 2];

                // merge 2 lowest level nodes if the level is lower or eqaul to the given level or if last 2 nodes levels are equal
                if (penultimate.Level <= level || penultimate.Level == last.Level)
                {
                    TreeNode parent = CreateParentNode(penultimate, last);
                    heads.RemoveAt(heads.Count - 1);
                    heads[heads.Count - 1] = parent;
                    last = parent;
                }
                else
                {
                    break;
                }
            }

            return last;
        }

        private static TreeNode GetSameLevelNode(TreeNode node, List<TreeNode> heads)
        {
            foreach (TreeNode n in heads)
            {
                if (n != node && n.Level == node.Level)
                {
                    return n;
                }
            }

            return null;
        }

        private TreeNode CreateParentNode(TreeNode leftNode, TreeNode rightNode)
        {
            uint parentLevel = Math.Max(leftNode.Level, rightNode.Level) + 1;

            TreeNode treeNode = new TreeNode(parentLevel);

            leftNode.Parent = treeNode;
            leftNode.IsLeftNode = true;

            rightNode.Parent = treeNode;
            rightNode.IsLeftNode = false;

            treeNode.Hash = DataHasher
                .AddData(leftNode.Hash.Imprint)
                .AddData(rightNode.Hash.Imprint)
                .AddData(Util.EncodeUnsignedLong(parentLevel))
                .GetHash();

            treeNode.Left = leftNode;
            treeNode.Right = rightNode;
            return treeNode;
        }
    }
}