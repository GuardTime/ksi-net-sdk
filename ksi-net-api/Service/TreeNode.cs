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

using System;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Merkle tree node. Used to build Merkle tree during local aggregation.
    /// </summary>
    public class TreeNode
    {
        /// <summary>
        /// Create aggregation tree node instance.
        /// </summary>
        /// <param name="level">Node level in the tree</param>
        public TreeNode(uint level)
        {
            Level = level;
        }

        /// <summary>
        /// Create aggregation tree node instance.
        /// </summary>
        /// <param name="hash">Data hash to be signed</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        public TreeNode(DataHash hash, uint level = 0)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }
            Hash = hash;
            Level = level;
        }

        /// <summary>
        /// Create aggregation tree node instance.
        /// </summary>
        /// <param name="metadata">Metadata to be added to hash chain</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        public TreeNode(IdentityMetadata metadata, uint level = 0)
        {
            if (metadata == null)
            {
                throw new ArgumentNullException(nameof(metadata));
            }
            Metadata = metadata;
            Level = level;
        }

        /// <summary>
        /// Metadata to be added to aggregation hash chain
        /// </summary>
        public IdentityMetadata Metadata { get; }

        /// <summary>
        /// Hash value of the node.
        /// </summary>
        public DataHash Hash { get; set; }

        /// <summary>
        /// Parent node
        /// </summary>
        public TreeNode Parent { get; set; }

        /// <summary>
        /// Left child node
        /// </summary>
        public TreeNode Left { get; set; }

        /// <summary>
        /// Right child node
        /// </summary>
        public TreeNode Right { get; set; }

        /// <summary>
        /// If true then current node is left child, otherwise it is right node
        /// </summary>
        public bool IsLeftNode { get; set; }

        /// <summary>
        /// Node level in the tree. Level for leaves is 0.
        /// </summary>
        public uint Level { get; }

        /// <summary>
        /// String representation of the node.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            string value;
            if (Hash == null)
            {
                if (Metadata == null)
                {
                    return nameof(TreeNode);
                }

                value = "M:" + Base16.Encode(Metadata.AggregationHashChainMetadata.EncodeValue());
            }
            else
            {
                value = Base16.Encode(Hash.Value);
            }
            return string.Format("{0}{1}:{2}", Level, IsLeftNode ? "L" : "R", value);
        }
    }
}