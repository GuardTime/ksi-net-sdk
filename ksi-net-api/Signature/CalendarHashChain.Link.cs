﻿/*
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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public sealed partial class CalendarHashChain
    {
        /// <summary>
        ///     Calendar hash chain link object.
        /// </summary>
        public class Link : ImprintTag
        {
            /// <summary>
            /// Create calendar hash chain link instance
            /// </summary>
            /// <param name="tag"></param>
            public Link(ITlvTag tag) : base(tag)
            {
                CheckTagType((uint)LinkDirection.Right, (uint)LinkDirection.Left);

                switch (Type)
                {
                    case (uint)LinkDirection.Left:
                        Direction = LinkDirection.Left;
                        break;
                    case (uint)LinkDirection.Right:
                        Direction = LinkDirection.Right;
                        break;
                }
            }

            /// <summary>
            /// Get link direction
            /// </summary>
            public LinkDirection Direction { get; }
        }
    }
}