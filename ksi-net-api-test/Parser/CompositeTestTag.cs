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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Test.Parser
{
    /// <summary>
    /// Tag for CompositeTag testing
    /// </summary>
    public class CompositeTestTag : CompositeTag
    {
        public CompositeTestTag CompositeTestTagValue { get; private set; }

        public CompositeTestTag(ITlvTag tag) : base(tag)
        {
            BuildStructure();
        }

        public CompositeTestTag(uint type, bool nonCritical, bool forward, ITlvTag[] childTags)
            : base(type, nonCritical, forward, childTags)
        {
            BuildStructure();
        }

        private void BuildStructure()
        {
            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case 0x5:
                        this[i] = CompositeTestTagValue = childTag as CompositeTestTag ?? new CompositeTestTag(childTag);
                        break;
                    case 0x2:
                    case 0x1:
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }
        }

        public void VerifyCriticalFlagWithoutTag()
        {
            VerifyUnknownTag(null);
        }
    }
}