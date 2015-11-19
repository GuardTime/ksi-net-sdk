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
                throw new TlvException("Invalid TLV tag: null.");
            }

            Type = tag.Type;
            NonCritical = tag.NonCritical;
            Forward = tag.Forward;
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
        ///     Encode TLV object value.
        /// </summary>
        /// <returns>TLV object value as bytes</returns>
        public abstract byte[] EncodeValue();

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

            if (Type != tag.Type || Forward != tag.Forward || NonCritical != tag.NonCritical)
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
    }
}