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
using System.Text;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    public partial class LocalAggregator
    {
        /// <summary>
        /// Aggregation tree node. Used to build Merkle tree during local aggregation.
        /// </summary>
        private class AggregationTreeNode
        {
            /// <summary>
            /// Create aggregation tree node instance.
            /// </summary>
            /// <param name="level">Node level in the tree</param>
            public AggregationTreeNode(uint level)
            {
                Level = level;
            }

            /// <summary>
            /// Create aggregation tree node instance.
            /// </summary>
            /// <param name="item">Aggregation item</param>
            public AggregationTreeNode(LocalAggregationItem item)
            {
                if (item == null)
                {
                    throw new ArgumentNullException(nameof(item));
                }
                Item = item;
            }

            /// <summary>
            /// Aggregation item.
            /// </summary>
            public LocalAggregationItem Item { get; }

            /// <summary>
            /// Hash value of the node.
            /// </summary>
            public DataHash NodeHash { get; set; }

            /// <summary>
            /// Parent node
            /// </summary>
            public AggregationTreeNode Parent { get; set; }

            /// <summary>
            /// Left child node
            /// </summary>
            public AggregationTreeNode Left { get; set; }

            /// <summary>
            /// Right child node
            /// </summary>
            public AggregationTreeNode Right { get; set; }

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
                return string.Format("{0}{1}:{2}", Level, IsLeftNode ? "L" : "R", Base16.Encode((Item?.DocumentHash ?? NodeHash).Imprint));
            }

            /// <summary>
            /// Short version of the string representation of the node.
            /// </summary>
            /// <returns></returns>
            private string ToShortString()
            {
                return ToString().Substring(0, 10);
            }

            private static List<AggregationTreeNode> ValidateChildNodes(AggregationTreeNode node)
            {
                List<AggregationTreeNode> children = new List<AggregationTreeNode>();

                if (node.Left != null)
                {
                    if (node != node.Left.Parent)
                    {
                        throw new Exception("Left child parent does not match current node.");
                    }

                    if (!node.Left.IsLeftNode)
                    {
                        throw new Exception("Left child is not marked as left.");
                    }

                    children.AddRange(ValidateChildNodes(node.Left));
                }

                if (node.Right != null)
                {
                    if (node != node.Right.Parent)
                    {
                        throw new Exception("Left child parent does not match current node.");
                    }

                    if (node.Right.IsLeftNode)
                    {
                        throw new Exception("Right child is not marked as right.");
                    }

                    children.AddRange(ValidateChildNodes(node.Right));
                }

                if (children.Count == 0)
                {
                    children.Add(node);
                }

                return children;
            }

            private static void ValidateTree(List<AggregationTreeNode> lowestLevelNodes)
            {
                AggregationTreeNode root = lowestLevelNodes[0];

                while (root.Parent != null)
                {
                    root = root.Parent;
                }

                List<AggregationTreeNode> children = ValidateChildNodes(root);

                if (children.Count != lowestLevelNodes.Count)
                {
                    throw new Exception("Invalid tree. Leaf count does not match.");
                }

                for (int i = 0; i < lowestLevelNodes.Count; i++)
                {
                    if (lowestLevelNodes[i] != children[i])
                    {
                        throw new Exception(string.Format("Invalid tree. Leaves at position {0} do not match.", i));
                    }
                }
            }

            public static string PrintTree(List<AggregationTreeNode> lowestLevelNodes)
            {
                ValidateTree(lowestLevelNodes);
                return PrintTree(lowestLevelNodes, 0);
            }

            private static string PrintTree(List<AggregationTreeNode> nodes, uint level)
            {
                if (nodes == null || nodes.Count == 0)
                {
                    return null;
                }

                StringBuilder sb = new StringBuilder();

                if (nodes.Count > 1)
                {
                    List<AggregationTreeNode> parentNodes = new List<AggregationTreeNode>();
                    foreach (AggregationTreeNode node in nodes)
                    {
                        bool isParentNextLevel = node.Parent.Level == level + 1;

                        if (!node.IsLeftNode && isParentNextLevel)
                        {
                            continue;
                        }

                        if (node.NodeHash == null || !isParentNextLevel)
                        {
                            // add dummy invisible node
                            parentNodes.Add(new AggregationTreeNode(level + 1)
                            {
                                Parent = node.Parent,
                                IsLeftNode = isParentNextLevel && parentNodes.Count % 2 == 0
                            });
                        }
                        else
                        {
                            parentNodes.Add(node.Parent);
                        }
                    }

                    if (parentNodes.Count > 0)
                    {
                        // print parents
                        sb.Append(PrintTree(parentNodes, level + 1));
                    }
                }

                // calculate spaces
                string prefix = string.Empty;
                string space = string.Empty;

                // 2^n - 1
                double spacesCount = (1 << (int)level) - 1;

                for (int i = 0; i < spacesCount; i++)
                {
                    prefix += "      ";
                    space += "            ";
                }

                sb.Append(prefix);

                bool isFirst = true;

                if (nodes.Count > 1)
                {
                    // print tree branches
                    foreach (AggregationTreeNode node in nodes)
                    {
                        bool isParentNextLevel = node.Parent.Level == level + 1;
                        if (isFirst)
                        {
                            isFirst = false;
                        }
                        else
                        {
                            // add spaces or horizontal line
                            if (node.IsLeftNode || node.Level == 0 || !isParentNextLevel)
                            {
                                sb.Append(space + "  ");
                            }
                            else
                            {
                                // horizontal line
                                sb.Append((space + "  ").Replace(" ", "‾"));
                            }
                        }

                        if (node.NodeHash != null || isParentNextLevel)
                        {
                            sb.Append(node.IsLeftNode ? "        / " : " \\        ");
                        }
                    }
                }

                sb.AppendLine();
                sb.Append(prefix);

                isFirst = true;

                // print nodes
                foreach (AggregationTreeNode node in nodes)
                {
                    if (isFirst)
                    {
                        isFirst = false;
                    }
                    else
                    {
                        sb.Append(space);
                    }

                    if (node.Parent == null || node.NodeHash != null)
                    {
                        sb.Append(node.ToShortString() + "  ");
                    }
                }

                sb.AppendLine();

                return sb.ToString();
            }
        }
    }
}