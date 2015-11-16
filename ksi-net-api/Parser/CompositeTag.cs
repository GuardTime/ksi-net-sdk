using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV element containing other TLV elements.
    /// </summary>
    public abstract class CompositeTag : TlvTag, IEnumerable<TlvTag>
    {
        private readonly IList<TlvTag> _value = new List<TlvTag>();

        /// <summary>
        ///     Create new composite TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV tag is null</exception>
        protected CompositeTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        /// <summary>
        ///     Create new composite TLV element from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element list</param>
        /// <exception cref="TlvException">thrown when input value is null</exception>
        protected CompositeTag(uint type, bool nonCritical, bool forward, IList<TlvTag> value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new TlvException("Invalid TLV element list: null.");
            }

            for (int i = 0; i < value.Count; i++)
            {
                if (value[i] == null)
                {
                    throw new TlvException("Invalid TLV in element list: null.");
                }
                _value.Add(value[i]);
            }
        }

        /// <summary>
        ///     Get or set TLV child object
        /// </summary>
        /// <param name="i">tlv element position</param>
        /// <returns>TLV element at given position</returns>
        /// <exception cref="TlvException">thrown when trying to set null as value in array</exception>
        public TlvTag this[int i]
        {
            get { return _value[i]; }
        }

        /// <summary>
        ///     Get TLV element list size
        /// </summary>
        public int Count
        {
            get { return _value.Count; }
        }

        /// <summary>
        ///     Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        public IEnumerator<TlvTag> GetEnumerator()
        {
            return _value.GetEnumerator();
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
        ///     Decode bytes to TLV list.
        /// </summary>
        /// <param name="bytes">TLV bytes</param>
        private void DecodeValue(byte[] bytes)
        {
            using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    _value.Add(tlvReader.ReadTag());
                }
            }
        }

        /// <summary>
        ///     Encode child TLV list to byte array.
        /// </summary>
        /// <returns>TLV list elements as byte array</returns>
        public override byte[] EncodeValue()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                for (int i = 0; i < Count; i++)
                {
                    writer.WriteTag(this[i]);
                }

                return ((MemoryStream)writer.BaseStream).ToArray();
            }
        }

        /// <summary>
        ///     Verify unknown tag for critical flag and throw exception.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected void VerifyCriticalFlag(TlvTag tag)
        {
            if (tag == null)
            {
                throw new TlvException("Invalid TLV tag: null.");
            }

            if (!tag.NonCritical)
            {
                throw new TlvException("Unknown tag type(" + tag.Type + ").");
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
                for (int i = 0; i < _value.Count; i++)
                {
                    res = 31 * res + (_value[i] == null ? 0 : _value[i].GetHashCode());
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
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
                builder.Append(Util.TabPrefixString(_value[i].ToString()));
                if (i < Count - 1)
                {
                    builder.AppendLine();
                }
            }

            return builder.ToString();
        }
    }
}