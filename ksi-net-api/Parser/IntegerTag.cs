using System;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Integer TLV element.
    /// </summary>
    public class IntegerTag : TlvTag, IEquatable<IntegerTag>
    {
        private readonly ulong _value;

        /// <summary>
        ///     Create new Integer TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV tag is null or encodeValue returns null</exception>
        public IntegerTag(TlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                throw new TlvException("Invalid TLV element encoded value: null.");
            }
            _value = Util.DecodeUnsignedLong(data, 0, data.Length);
        }

        /// <summary>
        ///     Create new Integer TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element unsigned long value</param>
        public IntegerTag(uint type, bool nonCritical, bool forward, ulong value)
            : base(type, nonCritical, forward)
        {
            _value = value;
        }

        /// <summary>
        ///     Get TLV element unsigned long value.
        /// </summary>
        public ulong Value
        {
            get { return _value; }
        }

        /// <summary>
        ///     Compare against Integer TLV element
        /// </summary>
        /// <param name="tag">Comparable integer TLV element</param>
        /// <returns>true if integer TLV element is equal</returns>
        public bool Equals(IntegerTag tag)
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

            return Type == tag.Type &&
                   Forward == tag.Forward &&
                   NonCritical == tag.NonCritical &&
                   Value == tag.Value;
        }

        /// <summary>
        ///     Encode element value ulong to byte array.
        /// </summary>
        /// <returns>ulong as byte array</returns>
        public override byte[] EncodeValue()
        {
            return Util.EncodeUnsignedLong(Value);
        }

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        ///     Compare against object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>Is given object equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as IntegerTag);
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

            builder.Append("]:");
            builder.Append("i").Append(Value);
            return builder.ToString();
        }

        /// <summary>
        ///     Compare integer TLV elements against each other.
        /// </summary>
        /// <param name="a">Integer TLV element</param>
        /// <param name="b">Integer TLV element</param>
        /// <returns>true if elements are equal</returns>
        public static bool operator ==(IntegerTag a, IntegerTag b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        ///     Compare integer TLV element non equity to another integer TLV element.
        /// </summary>
        /// <param name="a">Integer TLV element</param>
        /// <param name="b">Integer TLV element</param>
        /// <returns>true if elements are not equal</returns>
        public static bool operator !=(IntegerTag a, IntegerTag b)
        {
            return !(a == b);
        }
    }
}