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
            IntegerTag tag = obj as IntegerTag;
            if (tag == null)
            {
                return false;
            }

            return tag.Type == Type &&
                   tag.Forward == Forward &&
                   tag.NonCritical == NonCritical &&
                   tag.Value == Value;
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

        /// <summary>
        /// Cast TLV element to DateTime.
        /// </summary>
        /// <param name="tag">Integer TLV element</param>
        public static implicit operator DateTime(IntegerTag tag)
        {
            return Util.ConvertUnixTimeToDateTime(tag.Value);
        }

        /// <summary>
        /// Cast TLV element to ulong.
        /// </summary>
        /// <param name="tag">Integer TLV element</param>
        public static implicit operator ulong(IntegerTag tag)
        {
            return tag.Value;
        }

    }

}
