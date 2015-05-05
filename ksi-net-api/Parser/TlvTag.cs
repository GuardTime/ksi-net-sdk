using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Abstract base class for Java objects representing TLV elements.
    /// </summary>
    /// <typeparam name="T">type of data contained in the tag.</typeparam>
    public abstract class TlvTag<T> : ITlvTag
    {
        /// <summary>
        /// Tlv tag type.
        /// </summary>
        public uint Type { get; set; }
        /// <summary>
        /// Is tlv tag non critical.
        /// </summary>
        public bool NonCritical { get; set; }
        /// <summary>
        /// Is tlv forwarded.
        /// </summary>
        public bool Forward { get; set; }
        /// <summary>
        /// Tlv value.
        /// </summary>
        public T Value { get; set; }

        /// <summary>
        /// Initiates TLVTag object.
        /// </summary>
        /// <param name="type">tag type</param>
        /// <param name="nonCritical">is tag non critical</param>
        /// <param name="forward">is tag forwarded</param>
        /// <param name="value">tag data</param>
        protected TlvTag(uint type, bool nonCritical, bool forward, T value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
            Value = value;
        }

        /// <summary>
        /// Initiates TLVTag object from base tag.
        /// </summary>
        /// <param name="tag">base tag</param>
        protected TlvTag(ITlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            Type = tag.Type;
            NonCritical = tag.NonCritical;
            Forward = tag.Forward;
        } 

        /// <summary>
        /// Return string representation of TLV tag
        /// </summary>
        /// <returns>string representation of TLV tag</returns>
        public override string ToString()
        {
            var builder = new StringBuilder();
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

            return builder.ToString();
        }

        /// <summary>
        /// Parse binary data to TLVTag object.
        /// </summary>
        /// <param name="valueBytes">binary data</param>
        public abstract void DecodeValue(byte[] valueBytes);

        /// <summary>
        /// Get TLVTag as bytes.
        /// </summary>
        /// <returns>TLV tag data as byte array</returns>
        public abstract byte[] EncodeValue();
    }
}
