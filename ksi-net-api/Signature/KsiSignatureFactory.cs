using System;
using System.Collections.Generic;
using System.IO;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature
{
    public partial class KsiSignatureFactory
    {
        /// <summary>
        ///     Get KSI signature instance from stream.
        /// </summary>
        /// <param name="stream">signature data stream</param>
        /// <returns>KSI signature</returns>
        /// <exception cref="ArgumentNullException">thrown when stream is null</exception>
        public IKsiSignature Create(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            using (TlvReader reader = new TlvReader(stream))
            {
                return new KsiSignature(reader.ReadTag());
            }
        }

        /// <summary>
        ///     Get KSI signature instance from aggregation response payload.
        /// </summary>
        /// <param name="payload">aggregation response payload</param>
        /// <returns>KSI signature</returns>
        /// <exception cref="ArgumentNullException">thrown when stream is null</exception>
        public IKsiSignature Create(AggregationResponsePayload payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }

            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                for (int i = 0; i < payload.Count; i++)
                {
                    if (payload[i].Type > 0x800 && payload[i].Type < 0x900)
                    {
                        writer.WriteTag(payload[i]);
                    }
                }

                return new KsiSignature(new RawTag(KsiSignature.TagType, false, false, stream.ToArray()));
            }
        }

    }
}