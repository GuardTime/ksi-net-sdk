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

using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV element containing other TLV elements.
    /// </summary>
    [SuppressMessage("ReSharper", "VirtualMemberCallInContructor")]
    public abstract class CompositeTag : TlvTag, ICompositeTag
    {
        private readonly List<ITlvTag> _childTags = new List<ITlvTag>();

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected virtual uint ExpectedTagType => 0;

        /// <summary>
        /// Check tag type
        /// </summary>
        protected virtual void CheckTagType()
        {
            if (ExpectedTagType != 0)
            {
                CheckTagType(ExpectedTagType);
            }
        }

        /// <summary>
        ///     Create new composite TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected CompositeTag(ITlvTag tag) : base(tag)
        {
            CheckTagType();
            DecodeValue(tag.EncodeValue());
        }

        /// <summary>
        ///     Create new composite TLV element from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="childTags">child TLV element list</param>
        protected CompositeTag(uint type, bool nonCritical, bool forward, ITlvTag[] childTags)
            : base(type, nonCritical, forward)
        {
            CheckTagType();

            if (childTags == null)
            {
                throw new TlvException("Invalid TLV element list: null.");
            }

            TagCounter tagCounter = new TagCounter();

            foreach (ITlvTag tag in childTags)
            {
                if (tag == null)
                {
                    throw new TlvException("Invalid TLV in element list: null.");
                }

                _childTags.Add(ParseChild(tag) ?? tag);
                tagCounter[tag.Type]++;
            }

            Validate(tagCounter);
        }

        /// <summary>
        ///     Get or set TLV child object
        /// </summary>
        /// <param name="i">tlv element position</param>
        /// <returns>TLV element at given position</returns>
        public ITlvTag this[int i]
        {
            get { return _childTags[i]; }
            protected set { _childTags[i] = value; }
        }

        /// <summary>
        ///     Get TLV element list size
        /// </summary>
        public int Count => _childTags.Count;

        /// <summary>
        ///     Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        public IEnumerator<ITlvTag> GetEnumerator()
        {
            return _childTags.GetEnumerator();
        }

        /// <summary>
        ///     Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Parse child tag.
        /// </summary>
        /// <param name="childTag">Child tag</param>
        /// <returns></returns>
        protected virtual ITlvTag ParseChild(ITlvTag childTag)
        {
            VerifyUnknownTag(childTag);
            return childTag;
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        /// <param name="tagCounter"></param>
        protected virtual void Validate(TagCounter tagCounter)
        {
        }

        /// <summary>
        /// Create integer tag from the given tag or return the given tag if it is already integer tag.
        /// </summary>
        /// <param name="tag">Tag to create from.</param>
        protected static IntegerTag GetIntegerTag(ITlvTag tag)
        {
            return tag as IntegerTag ?? new IntegerTag(tag);
        }

        /// <summary>
        /// Create raw tag from the given tag or return the given tag if it is already raw tag.
        /// </summary>
        /// <param name="tag">Tag to create from.</param>
        protected static RawTag GetRawTag(ITlvTag tag)
        {
            return tag as RawTag ?? new RawTag(tag);
        }

        /// <summary>
        /// Create string tag from the given tag or return the given tag if it is already string tag.
        /// </summary>
        /// <param name="tag">Tag to create from.</param>
        protected static StringTag GetStringTag(ITlvTag tag)
        {
            return tag as StringTag ?? new StringTag(tag);
        }

        /// <summary>
        /// Create imprint tag from the given tag or return the given tag if it is already imprint tag.
        /// </summary>
        /// <param name="tag">Tag to create from.</param>
        protected static ImprintTag GetImprintTag(ITlvTag tag)
        {
            return tag as ImprintTag ?? new ImprintTag(tag);
        }

        /// <summary>
        ///     Decode bytes to TLV list.
        /// </summary>
        /// <param name="bytes">TLV bytes</param>
        private void DecodeValue(byte[] bytes)
        {
            TagCounter tagCounter = new TagCounter();

            using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    RawTag tag = tlvReader.ReadTag();
                    _childTags.Add(ParseChild(tag) ?? tag);
                    tagCounter[tag.Type]++;
                }
            }

            Validate(tagCounter);
        }

        /// <summary>
        ///     Encode child TLV list to byte array.
        /// </summary>
        /// <returns>TLV list elements as byte array</returns>
        public override byte[] EncodeValue()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                foreach (ITlvTag tag in _childTags)
                {
                    writer.WriteTag(tag);
                }

                return ((MemoryStream)writer.BaseStream).ToArray();
            }
        }

        /// <summary>
        ///     Verify unknown tag for critical flag and throw exception.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected void VerifyUnknownTag(ITlvTag tag)
        {
            if (tag == null)
            {
                throw new TlvException("Invalid TLV tag: null.");
            }

            if (!tag.NonCritical)
            {
                throw new TlvException("Unknown tag type (0x" + tag.Type.ToString("X") + ").");
            }
        }

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                int res = 1;
                foreach (ITlvTag tag in _childTags)
                {
                    res = 31 * res + tag.GetHashCode();
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        /// Returns all child objects as an array
        /// </summary>
        /// <returns></returns>
        public ITlvTag[] GetChildrenArray()
        {
            return _childTags.ToArray();
        }

        /// <summary>
        ///     Convert TLV element to string.
        /// </summary>
        /// <returns>TLV element as string</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("TLV[0x").Append(Type.ToString("X"));

            if (NonCritical)
            {
                builder.Append(",N");
            }

            if (Forward)
            {
                builder.Append(",F");
            }

            builder.Append("]:").AppendLine();

            for (int i = 0; i < Count; i++)
            {
                builder.Append(Util.TabPrefixString(_childTags[i].ToString()));
                if (i < Count - 1)
                {
                    builder.AppendLine();
                }
            }

            return builder.ToString();
        }
    }
}