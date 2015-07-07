using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// TLV element containing other TLV elements
    /// </summary>
    public abstract class CompositeTag : TlvTag, IEnumerable<TlvTag>
    {
        private readonly object _lock = new object();

        private readonly List<TlvTag> _value = new List<TlvTag>();

        // TODO: Make checks for array and do not allow to write to object from outside
        // TODO: Make it thread safe?
        /// <summary>
        /// Get or set TLV child object
        /// </summary>
        /// <param name="i">tlv element position</param>
        /// <returns>TLV element at given position</returns>
        public TlvTag this[int i]
        {
            get {
                lock (_lock)
                {
                    return _value[i];
                }
            }

            protected set {
                lock (_lock)
                {
                    if (value == null)
                    {
                        throw new ArgumentNullException("value");
                    }

                    _value[i] = value;
                }
            }
        }

        // TODO: can be null?
        /// <summary>
        /// Get TLV element list size
        /// </summary>
        public int Count
        {
            get { return _value.Count; }
        }


        // TODO: Create possibility to check composite tag validity and check for null tags in child objects
        /// <summary>
        /// Create new composite TLV element from tlv element
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected CompositeTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        /// <summary>
        /// Create new composite TLV element from data
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV value</param>
        protected CompositeTag(uint type, bool nonCritical, bool forward, List<TlvTag> value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            _value = value;
        }

        private void DecodeValue(byte[] bytes)
        {
            
            using (MemoryStream stream = new MemoryStream(bytes))
            using (TlvReader tlvReader = new TlvReader(stream))
            {
                while (stream.Position < stream.Length)
                {
                    _value.Add(tlvReader.ReadTag());
                }
            }
        }

        /// <summary>
        /// Encode child TLV list to byte array
        /// </summary>
        /// <returns>TLV list elements as byte array</returns>
        public override byte[] EncodeValue()
        {
            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                for (int i = 0; i < Count; i++)
                {
                    writer.WriteTag(this[i]);
                }

                return stream.ToArray();
            }
        }

        /// <summary>
        /// Check TLV structure.
        /// </summary>
        protected abstract void CheckStructure();

        /// <summary>
        /// Is TLV element structure valid.
        /// </summary>
        public void IsValidStructure()
        {
            try
            {
                CheckStructure();
                for (int i = 0; i < Count; i++)
                {
                    CompositeTag tag = this[i] as CompositeTag;
                    if (tag == null) continue;


                    tag.IsValidStructure();
                }

            }
            catch (InvalidTlvStructureException e)
            {
                e.TlvList.Add(this);
                throw;
            }
        }

        // TODO: Use better name
        /// <summary>
        /// Put TLV element to child list, if null, remove it from list.
        /// </summary>
        /// <typeparam name="T">TLV element type</typeparam>
        /// <param name="tag">New TLV element to put in list</param>
        /// <param name="previousTag">Previous TLV element in list</param>
        /// <returns>Added Tlv element</returns>
        protected T PutTag<T>(T tag, TlvTag previousTag) where T : TlvTag
        {
            if (ReplaceTag(tag, previousTag) == null)
            {
                AddTag(tag);
            }

            return tag;
        }

        /// <summary>
        /// Add TLV element to list.
        /// </summary>
        /// <typeparam name="T">Tlv element type</typeparam>
        /// <param name="tag">New TLV element</param>
        /// <returns>Added TLV element</returns>
        protected T AddTag<T>(T tag) where T : TlvTag
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            _value.Add(tag);
            return tag;
        }

        /// <summary>
        /// Replace TLV element in list.
        /// </summary>
        /// <typeparam name="T">TLV element type</typeparam>
        /// <param name="tag">New TLV element</param>
        /// <param name="previousTag">Previous TLV element in list</param>
        /// <returns>Replaced TLV element</returns>
        protected T ReplaceTag<T>(T tag, TlvTag previousTag) where T : TlvTag
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            if (previousTag == null)
            {
                return null;
            }

            int i = _value.IndexOf(previousTag);
            if (i == -1)
            {
                return null;
            }

            _value[i] = tag;
            return tag;
        }

        /// <summary>
        /// Remove TLV element from list.
        /// </summary>
        /// <typeparam name="T">TLV element type</typeparam>
        /// <param name="tag">TLV element in list</param>
        protected void RemoveTag<T>(T tag) where T : TlvTag
        {
            if (tag != null)
            {
                _value.Remove(tag);
            }
        }

        /// <summary>
        /// Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        public IEnumerator<TlvTag> GetEnumerator()
        {
            return _value.GetEnumerator();
        }

        /// <summary>
        /// Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Get TLV element hash code.
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
        /// Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>Is given object equal</returns>
        public override bool Equals(object obj)
        {
            CompositeTag tag = obj as CompositeTag;
            if (tag == null || (tag.Type != Type && tag.Forward != Forward && tag.NonCritical != NonCritical))
            {
                return false;
            }
            
            IEnumerator<TlvTag> tagEnumerator = tag._value == null ? new EmptyEnumerator<TlvTag>() : tag.GetEnumerator();
            IEnumerator<TlvTag> enumerator = _value == null ? new EmptyEnumerator<TlvTag>() : GetEnumerator();
            bool match = true;
            while (match && tagEnumerator.MoveNext() && enumerator.MoveNext())
            {
                TlvTag value1 = tagEnumerator.Current;
                TlvTag value2 = enumerator.Current;
                match = value1 == null ? value2 == null : value1.Equals(value2);
            }

            return match;
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

            builder.Append("]:").Append('\n');

            for (int i = 0; i < Count; i++)
            {
                builder.Append(TabPrefix(_value[i].ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        private string TabPrefix(string s)
        {
            StringBuilder builder = new StringBuilder();

            string[] lines = s.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                builder.Append("  ");
                builder.Append(lines[i]);
                if (!lines[i].Equals(lines[lines.Length - 1]))
                {
                    builder.Append("\n");
                }
            }

            return builder.ToString();
        }


        
    }

}
