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
    public abstract class CompositeTag : TlvTag, IEnumerable<TlvTag>, IEquatable<CompositeTag>
    {
        private readonly object _lock = new object();
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
            get
            {
                lock (_lock)
                {
                    return _value[i];
                }
            }

            // TODO: Thread safe
            protected set
            {
                lock (_lock)
                {
                    if (value == null)
                    {
                        throw new TlvException("Invalid TLV value: null.");
                    }

                    _value[i] = value;
                }
            }
        }

        /// <summary>
        ///     Get TLV element list size
        /// </summary>
        public int Count
        {
            get
            {
                lock (_lock)
                {
                    return _value.Count;
                }
            }
        }

        /// <summary>
        ///     Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        public IEnumerator<TlvTag> GetEnumerator()
        {
            return new ThreadSafeIEnumerator<TlvTag>(_value.GetEnumerator(), _lock);
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
        ///     Compare Composite element to composite element
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
        ///     Decode bytes to TLV list.
        /// </summary>
        /// <param name="bytes">TLV bytes</param>
        private void DecodeValue(byte[] bytes)
        {
            MemoryStream stream = null;

            try
            {
                stream = new MemoryStream(bytes);
                using (TlvReader tlvReader = new TlvReader(stream))
                {
                    stream = null;
                    while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                    {
                        _value.Add(tlvReader.ReadTag());
                    }
                }
            }
            finally
            {
                if (stream != null)
                {
                    stream.Dispose();
                }
            }
        }

        /// <summary>
        ///     Encode child TLV list to byte array.
        /// </summary>
        /// <returns>TLV list elements as byte array</returns>
        public override byte[] EncodeValue()
        {
            MemoryStream stream = null;
            try
            {
                stream = new MemoryStream();
                using (TlvWriter writer = new TlvWriter(stream))
                {
                    stream = null;
                    for (int i = 0; i < Count; i++)
                    {
                        writer.WriteTag(this[i]);
                    }

                    return ((MemoryStream) writer.BaseStream).ToArray();
                }
            }
            finally
            {
                if (stream != null)
                {
                    stream.Dispose();
                }
            }
        }

        // TODO: Use better name or replace this functionality
        /// <summary>
        ///     Put TLV element to child list, if null, remove it from list.
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
        ///     Add TLV element to list.
        /// </summary>
        /// <typeparam name="T">Tlv element type</typeparam>
        /// <param name="tag">New TLV element</param>
        /// <returns>Added TLV element</returns>
        /// <exception cref="TlvException">thrown when TLV tag is null</exception>
        protected T AddTag<T>(T tag) where T : TlvTag
        {
            lock (_lock)
            {
                if (tag == null)
                {
                    throw new TlvException("Invalid TLV tag: null.");
                }

                _value.Add(tag);
                return tag;
            }
        }

        /// <summary>
        ///     Replace TLV element in list.
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
                    res = 31*res + (_value[i] == null ? 0 : _value[i].GetHashCode());
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        ///     Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>Is given object equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as CompositeTag);
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


        /// <summary>
        ///     Compare two composite element objects.
        /// </summary>
        /// <param name="a">composite element</param>
        /// <param name="b">composite element</param>
        /// <returns>true if objects are equal</returns>
        public static bool operator ==(CompositeTag a, CompositeTag b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        ///     Compare two composite elements non equality.
        /// </summary>
        /// <param name="a">composite element</param>
        /// <param name="b">composite element</param>
        /// <returns>true if objects are not equal</returns>
        public static bool operator !=(CompositeTag a, CompositeTag b)
        {
            return !(a == b);
        }

        /// <summary>
        ///     Thread safe enumerator for composite tag element
        /// </summary>
        /// <typeparam name="T">composite element</typeparam>
        private class ThreadSafeIEnumerator<T> : IEnumerator<T>
        {
            private readonly IEnumerator<T> _childEnumerator;
            private readonly object _lock;

            public ThreadSafeIEnumerator(IEnumerator<T> childEnumerator, object lockObject)
            {
                _childEnumerator = childEnumerator;
                _lock = lockObject;

                Monitor.Enter(_lock);
            }

            public T Current
            {
                get { return _childEnumerator.Current; }
            }

            object IEnumerator.Current
            {
                get { return _childEnumerator.Current; }
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