using Guardtime.KSI.Utils;
using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Integer TLV element.
    /// </summary>
    public class IntegerTag : TlvTag
    {
        private readonly ulong _value;

        /// <summary>
        /// Get TLV element unsigned long value.
        /// </summary>
        public ulong Value
        {
            get { return _value; }
        }

        /// <summary>
        /// Create new Integer TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public IntegerTag(TlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                // TODO: Check exception message
                throw new ArgumentException("Invalid TLV element encoded value: null", "tag");
            }
            _value = Util.DecodeUnsignedLong(data, 0, data.Length);
        }

        /// <summary>
        /// Create new Integer TLV element from data.
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
        /// Encode element value ulong to byte array.
        /// </summary>
        /// <returns>ulong as byte array</returns>
        public override byte[] EncodeValue()
        {
            return Util.EncodeUnsignedLong(Value);
        }

        /// <summary>
        /// Get TLV element hash code.
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
        /// Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object</param>
        /// <returns>Is TLV element equal to object</returns>
        public override bool Equals(object obj)
        {
            return this == obj as IntegerTag;
        }

        /// <summary>
        /// Convert TLV element to string.
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

        public static bool operator ==(IntegerTag a, IntegerTag b)
        {
            // If both are null, or both are same instance, return true.
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            // If one is null, but not both, return false.
            if (((object)a == null) || ((object)b == null))
            {
                return false;
            }

            return a.Type == b.Type &&
                    a.Forward == b.Forward &&
                    a.NonCritical == b.NonCritical &&
                    a.Value == b.Value;
        }

        public static bool operator !=(IntegerTag a, IntegerTag b)
        {
            return !(a == b);
        }


    }

}
