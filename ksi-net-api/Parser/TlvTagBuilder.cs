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

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Class for building TLV tags based on a given TLV tag.
    /// </summary>
    public class TlvTagBuilder
    {
        private readonly uint _type;
        private readonly bool _nonCritical;
        private readonly bool _forward;
        private readonly List<ITlvTag> _childTags;

        /// <summary>
        /// Create new TLV tag builder.
        /// </summary>
        /// <param name="tag">TLV tag to be used as base tag</param>
        public TlvTagBuilder(CompositeTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag));
            }

            _type = tag.Type;
            _nonCritical = tag.NonCritical;
            _forward = tag.Forward;
            _childTags = new List<ITlvTag>(tag);
        }

        /// <summary>
        /// Create new TLV tag builder.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="childTags">child TLV element list</param>
        public TlvTagBuilder(uint type, bool nonCritical, bool forward, ITlvTag[] childTags)
        {
            if (childTags == null)
            {
                throw new ArgumentNullException(nameof(childTags));
            }
            _type = type;
            _nonCritical = nonCritical;
            _forward = forward;
            _childTags = new List<ITlvTag>(childTags);
        }

        /// <summary>
        /// Add child TLV tag to the list of children tags.
        /// </summary>
        /// <param name="childTag">Child TLV tag to be added</param>
        public void AddChildTag(ITlvTag childTag)
        {
            if (childTag == null)
            {
                throw new ArgumentNullException(nameof(childTag));
            }
            _childTags.Add(childTag);
        }

        /// <summary>
        /// Get the first child TLV tag of a given type.
        /// </summary>
        /// <param name="type">TLV tag type to be searched</param>
        /// <returns></returns>
        public ITlvTag GetChildByType(uint type)
        {
            for (int i = 0; i < _childTags.Count; i++)
            {
                ITlvTag childTag = _childTags[i];
                if (childTag.Type == type)
                {
                    return childTag;
                }
            }

            return null;
        }

        /// <summary>
        /// Replace child TLV tag with given TLV tag. Reference equality is used when searching the tag to be replaced.
        /// </summary>
        /// <param name="oldTag">TLV tag to be replaced</param>
        /// <param name="newTag">TLV tag to replace the oldTag. If multiple oldTag occurarences exist then only the first one is replaced.</param>
        public void ReplaceChildTag(ITlvTag oldTag, ITlvTag newTag)
        {
            if (oldTag == null)
            {
                throw new ArgumentNullException(nameof(oldTag));
            }

            if (newTag == null)
            {
                throw new ArgumentNullException(nameof(newTag));
            }

            for (int i = 0; i < _childTags.Count; i++)
            {
                if (ReferenceEquals(_childTags[i], oldTag))
                {
                    _childTags[i] = newTag;
                    return;
                }
            }
        }

        /// <summary>
        /// Remove given child TLV tag. Reference equality is used when searching the tag to be removed.
        /// </summary>
        /// <param name="childTag"></param>
        public void RemoveChildTag(ITlvTag childTag)
        {
            if (childTag == null)
            {
                throw new ArgumentNullException(nameof(childTag));
            }

            for (int i = 0; i < _childTags.Count; i++)
            {
                if (ReferenceEquals(childTag, _childTags[i]))
                {
                    _childTags.RemoveAt(i);
                    return;
                }
            }
        }

        /// <summary>
        /// Get all child tags. The returned tags are NOT cloned.
        /// </summary>
        /// <returns></returns>
        public ITlvTag[] GetChildTags()
        {
            return _childTags.ToArray();
        }

        /// <summary>
        /// Build new TLV tag as RawTag.
        /// </summary>
        /// <returns></returns>
        public RawTag BuildTag()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                foreach (ITlvTag tag in _childTags)
                {
                    writer.WriteTag(tag);
                }

                return new RawTag(_type, _nonCritical, _forward, ((MemoryStream)writer.BaseStream).ToArray());
            }
        }
    }
}