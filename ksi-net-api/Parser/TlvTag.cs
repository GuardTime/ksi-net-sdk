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
using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV objects base class.
    /// </summary>
    public abstract class TlvTag : ITlvTag, IEquatable<TlvTag>
    {
        /// <summary>
        ///     Create new TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        protected TlvTag(uint type, bool nonCritical, bool forward)
        {
            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
        }

        /// <summary>
        ///     Create new TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected TlvTag(ITlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag));
            }

            Type = tag.Type;
            NonCritical = tag.NonCritical;
            Forward = tag.Forward;
        }

        /// <summary>
        /// Checks if TLV tag type is valid and throws a TLV exception if the type is invalid.
        /// </summary>
        /// <param name="expectedTagType"></param>
        protected void CheckTagType(params uint[] expectedTagType)
        {
            bool isValid = false;
            foreach (uint type in expectedTagType)
            {
                if (Type == type)
                {
                    isValid = true;
                    break;
                }
            }

            if (!isValid)
            {
                ThrowInvalidTypeException();
            }
        }

        /// <summary>
        /// Throw TLV exception indicating to an invalid TLV type.
        /// </summary>
        private void ThrowInvalidTypeException()
        {
            Type type = GetType();
            string typeName = type.Name;

            // ReSharper disable once ConditionIsAlwaysTrueOrFalse
            while (type.DeclaringType != null)
            {
                type = type.DeclaringType;
                typeName = type.Name + "." + typeName;
            }

            throw new TlvException(string.Format("Invalid tag type! Class: {0}; Type: 0x{1};", typeName, Type.ToString("X")));
        }

        /// <summary>
        ///     Tlv tag type.
        /// </summary>
        public uint Type { get; }

        /// <summary>
        ///     Is tlv tag non critical.
        /// </summary>
        public bool NonCritical { get; }

        /// <summary>
        ///     Is tlv forwarded.
        /// </summary>
        public bool Forward { get; }

        /// <summary>
        /// Is TLV16 encoding forced when writing the TLV object
        /// </summary>
        public virtual bool ForceTlv16Encoding => false;

        /// <summary>
        ///     Encode TLV object value.
        /// </summary>
        /// <returns>TLV object value as bytes</returns>
        public abstract byte[] EncodeValue();

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public abstract override int GetHashCode();

        /// <summary>
        ///     Encode TLV object.
        /// </summary>
        /// <returns>TLV object as bytes</returns>
        public byte[] Encode()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(this);
                return ((MemoryStream)writer.BaseStream).ToArray();
            }
        }

        /// <summary>
        ///     Compare tlv element to tlv element
        /// </summary>
        /// <param name="tag">composite element</param>
        /// <returns>true if objects are equal</returns>
        public bool Equals(TlvTag tag)
        {
            // If parameter is null, return false. 
            if (ReferenceEquals(tag, null))
            {
                return false;
            }

            if (ReferenceEquals(this, tag))
            {
                return true;
            }

            // If run-time types are not exactly the same, return false. 
            if (GetType() != tag.GetType())
            {
                return false;
            }

            if (Type != tag.Type || NonCritical != tag.NonCritical || Forward != tag.Forward)
            {
                return false;
            }

            byte[] valueBytes = EncodeValue();
            byte[] tagValueBytes = tag.EncodeValue();

            return Util.IsArrayEqual(valueBytes, tagValueBytes);
        }

        /// <summary>
        ///     Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>Is given object equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as TlvTag);
        }

        /// <summary>
        ///     Compare two composite element objects.
        /// </summary>
        /// <param name="a">composite element</param>
        /// <param name="b">composite element</param>
        /// <returns>true if objects are equal</returns>
        public static bool operator ==(TlvTag a, TlvTag b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        ///     Compare two composite elements non equality.
        /// </summary>
        /// <param name="a">composite element</param>
        /// <param name="b">composite element</param>
        /// <returns>true if objects are not equal</returns>
        public static bool operator !=(TlvTag a, TlvTag b)
        {
            return !(a == b);
        }

        /// <summary>
        ///     Convert TLV object to string.
        /// </summary>
        /// <returns>TLV object as string</returns>
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

            builder.Append("]:");
            builder.Append("0x").Append(Base16.Encode(EncodeValue()));

            return builder.ToString();
        }

        /// <summary>
        ///     Write TlvTag to stream.
        /// </summary>
        /// <param name="outputStream">output stream</param>
        public void WriteTo(Stream outputStream)
        {
            if (outputStream == null)
            {
                throw new ArgumentNullException(nameof(outputStream));
            }

            if (!outputStream.CanWrite)
            {
                throw new KsiException("Output stream is not writable.");
            }

            // Cannot use "using", otherwise outputStream will be closed
            TlvWriter writer = new TlvWriter(outputStream);
            writer.WriteTag(this);
        }
    }
}