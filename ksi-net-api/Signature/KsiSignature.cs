using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using System.IO;
using System;

namespace Guardtime.KSI.Signature
{
    public class KsiSignature
    {
        private readonly KsiSignatureDo _ksiSignatureDo;

        public ulong AggregationTime {
            get { return _ksiSignatureDo.AggregationTime; }
        }

        public KsiSignature(KsiPduPayload response)
        {
            List<TlvTag> signatureTags = new List<TlvTag>();
            for (int i = 0; i < response.Count; i++)
            {
                if (response[i].Type > 0x800 && response[i].Type < 0x900)
                {
                    signatureTags.Add(response[i]);
                }
            }

            _ksiSignatureDo = new KsiSignatureDo(signatureTags);
            _ksiSignatureDo.IsValidStructure();
        }

        // TODO: Should be public?
        private KsiSignature(KsiSignatureDo ksiSignatureDo)
        {
            if (ksiSignatureDo == null)
            {
                throw new ArgumentNullException("ksiSignatureDo");
            }
            // TODO: Should check structure?
            ksiSignatureDo.IsValidStructure();
            _ksiSignatureDo = ksiSignatureDo;
        }

        public KsiSignature Extend(CalendarHashChain calendarHashChain)
        {
            if (calendarHashChain == null)
            {
                throw new ArgumentNullException("calendarHashChain");
            }

            List<TlvTag> signatureTags = new List<TlvTag>();
            for (int i = 0; i < _ksiSignatureDo.Count; i++)
            {
                // TODO: Change type to constant
                if (_ksiSignatureDo[i].Type == 0x802)
                {
                    signatureTags.Add(calendarHashChain);
                    continue;
                }

                signatureTags.Add(_ksiSignatureDo[i]);
            }

            return new KsiSignature(new KsiSignatureDo(signatureTags));
        }

        public static KsiSignature GetInstance(Stream stream)
        {
            // TODO: Java api check if stream is null
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            using (TlvReader reader = new TlvReader(stream))
            {
                KsiSignatureDo ksiSignatureDo = new KsiSignatureDo(reader.ReadTag());
                ksiSignatureDo.IsValidStructure();
                return new KsiSignature(ksiSignatureDo);
            }
        }

        public override string ToString()
        {
            return _ksiSignatureDo.ToString();
        }
    }
}
