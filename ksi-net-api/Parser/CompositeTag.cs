using System;
using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;
using System.Collections.Generic;
using System.Collections;
using System.Threading;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// TLV element containing other TLV elements
    /// </summary>
    public abstract class CompositeTag : TlvTag, IEnumerable<TlvTag>, IEquatable<CompositeTag>
    {
        private readonly object _lock = new object();
        private readonly List<TlvTag> _value = new List<TlvTag>();

        /// <summary>
        /// Get or set TLV child object
        /// </summary>
        /// <param name="i">tlv element position</param>
        /// <returns>TLV element at given position</returns>
        public TlvTag this[int i]
        {
            get
            {
                lock (_lock)
                {
                    return _value[i];
                }
            }

            protected set
            {
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

        /// <summary>
        /// Get TLV element list size
        /// </summary>
        public int Count
        {
            get {
                lock (_lock)
                {
                    return _value.Count;
                }
            }
        }

        /// <summary>
        /// Create new composite TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected CompositeTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        /// <summary>
        /// Create new composite TLV element from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element list</param>
        protected CompositeTag(uint type, bool nonCritical, bool forward, List<TlvTag> value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            _value = value;
        }

        /// <summary>
        /// Decode bytes to TLV list.
        /// </summary>
        /// <param name="bytes">TLV bytes</param>
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
        /// Encode child TLV list to byte array.
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

        // TODO: Use better name or replace this functionality
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
            lock (_lock)
            {
                if (tag == null)
                {
                    throw new ArgumentNullException("tag");
                }

                _value.Add(tag);
                return tag;
            }
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
            lock (_lock)
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
        }

        /// <summary>
        /// Verify unknown tag for critical flag and throw exception.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected void VerifyCriticalFlag(TlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            if (!tag.NonCritical)
            {
                throw new InvalidTlvStructureException("Invalid tag", tag);
            }

            
        }

        /// <summary>
        /// Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        public IEnumerator<TlvTag> GetEnumerator()
        {
            return new ThreadSafeIEnumerator<TlvTag>(_value.GetEnumerator(), _lock);
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
            return Equals(obj as CompositeTag);
        }

        /// <summary>
        /// Compare Composite element to composite element
        /// </summary>
        /// <param name="tag">composite element</param>
        /// <returns>true if objects are equal</returns>
        public bool Equals(CompositeTag tag)
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

            if (Count != tag.Count || Type != tag.Type || Forward != tag.Forward || NonCritical != tag.NonCritical)
            {
                return false;
            }

            for (int i = 0; i < Count; i++)
            {
                if (!this[i].Equals(tag[i]))
                {
                    return false;
                }
            }

            return true;
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

        /// <summary>
        /// Put tab prefix instead of new rows.
        /// </summary>
        /// <param name="s">string</param>
        /// <returns>tab prefixed string</returns>
        private static string TabPrefix(string s)
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

        /// <summary>
        /// Compare two composite element objects.
        /// </summary>
        /// <param name="a">composite element</param>
        /// <param name="b">composite element</param>
        /// <returns>true if objects are equal</returns>
        public static bool operator ==(CompositeTag a, CompositeTag b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        /// Compare two composite elements non equality.
        /// </summary>
        /// <param name="a">composite element</param>
        /// <param name="b">composite element</param>
        /// <returns>true if objects are not equal</returns>
        public static bool operator !=(CompositeTag a, CompositeTag b)
        {
            return !(a == b);
        }

        /// <summary>
        /// Thread safe enumerator for composite tag element
        /// </summary>
        /// <typeparam name="T">composite element</typeparam>
        private class ThreadSafeIEnumerator<T> : IEnumerator<T>
        {
            private readonly object _lock;
            private readonly IEnumerator<T> _childEnumerator;

            public T Current
            {
                get
                {
                    return _childEnumerator.Current;
                }
            }

            object IEnumerator.Current
            {
                get
                {
                    return _childEnumerator.Current;
                }
            }

            public ThreadSafeIEnumerator(IEnumerator<T> childEnumerator, object lockObject)
            {
                _childEnumerator = childEnumerator;
                _lock = lockObject;

                Monitor.Enter(_lock);
            }

            public void Dispose()
            {
                Monitor.Exit(_lock);
            }

            public bool MoveNext()
            {
                return _childEnumerator.MoveNext();
            }

            public void Reset()
            {
                _childEnumerator.Reset();
            }
        }
    }

}
