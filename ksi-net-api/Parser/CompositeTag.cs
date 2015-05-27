using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Parser
{
    public abstract class CompositeTag : TlvTag
    {
        private readonly List<TlvTag> _value;
        // TODO: Make list thread safe
        public new List<TlvTag> Value
        {
            get { return _value; }
        }

        // TODO: Create possibility to check composite tag validity and check for null tags in child objects
        protected CompositeTag(byte[] bytes) : base(bytes)
        {
            _value = new List<TlvTag>();
            DecodeValue(base.Value);
        }

        protected CompositeTag(TlvTag tag) : base(tag)
        {
            _value = new List<TlvTag>();
            DecodeValue(tag.EncodeValue());
        }

        protected CompositeTag(uint type, bool nonCritical, bool forward, List<TlvTag> value)
            : base(type, nonCritical, forward, EncodeTlvTagList(value))
        {
            _value = value;
        }

        private void DecodeValue(byte[] bytes)
        {
            
            using (MemoryStream stream = new MemoryStream(bytes))
            using (TlvReader tlvReader = new TlvReader(stream))
            {
                while (stream.Position < stream.Length)
                {
                    Value.Add(tlvReader.ReadTag());
                }
            }
        }

        public override byte[] EncodeValue()
        {
            return EncodeTlvTagList(Value);
        }

        protected abstract void CheckStructure();

        public void IsValidStructure()
        {
            try
            {
                CheckStructure();
                for (int i = 0; i < Value.Count; i++)
                {
                    CompositeTag tag = Value[i] as CompositeTag;
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
        protected T PutTag<T>(T tag, TlvTag previousTag) where T : TlvTag
        {
            if (tag == null && previousTag != null)
            {
                RemoveTag(previousTag);
                return null;
            }

            if (ReplaceTag(tag, previousTag) == null && tag != null)
            {
                AddTag(tag);
            }

            return tag;

        }

        protected T AddTag<T>(T tag) where T : TlvTag
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            Value.Add(tag);
            return tag;
        }

        protected T ReplaceTag<T>(T tag, TlvTag previousTag) where T : TlvTag
        {
            if (previousTag == null)
            {
                return null;
            }

            int i = Value.IndexOf(previousTag);
            if (i == -1)
            {
                return null;
            }

            Value[i] = tag;
            return tag;
        }

        protected void RemoveTag<T>(T tag) where T : TlvTag
        {
            if (tag != null)
            {
                Value.Remove(tag);
            }
        }

        private static byte[] EncodeTlvTagList(IList<TlvTag> list)
        {
            if (list == null)
            {
                return null;
            }

            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                for (int i = 0; i < list.Count; i++)
                {
                    writer.WriteTag(list[i]);
                }

                return stream.ToArray();
            }
        }

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

        public override bool Equals(object obj)
        {
            CompositeTag tag = obj as CompositeTag;
            if (tag == null || (tag.Type != Type && tag.Forward != Forward && tag.NonCritical != NonCritical))
            {
                return false;
            }
            
            IEnumerator<TlvTag> tagEnumerator = tag.Value == null ? (IEnumerator<TlvTag>) new Util.EmptyEnumerator<TlvTag>() : tag.Value.GetEnumerator();
            IEnumerator<TlvTag> enumerator = Value == null ? (IEnumerator<TlvTag>) new Util.EmptyEnumerator<TlvTag>() : Value.GetEnumerator();
            bool match = true;
            while (match && tagEnumerator.MoveNext() && enumerator.MoveNext())
            {
                TlvTag value1 = tagEnumerator.Current;
                TlvTag value2 = enumerator.Current;
                match = value1 == null ? value2 == null : value1.Equals(value2);
            }

            return match;
        }

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

            for (int i = 0; i < Value.Count; i++)
            {
                builder.Append(TabPrefix(Value[i].ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s)
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
