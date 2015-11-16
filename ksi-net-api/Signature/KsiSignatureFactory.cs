using System.IO;
using Guardtime.KSI.Exceptions;
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
        /// <exception cref="KsiException">thrown when stream is null</exception>
        public IKsiSignature Create(Stream stream)
        {
            if (stream == null)
            {
                throw new KsiException("Invalid input stream: null.");
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
        /// <exception cref="KsiException">thrown when aggregation response payload is null</exception>
        public IKsiSignature Create(AggregationResponsePayload payload)
        {
            if (payload == null)
            {
                throw new KsiException("Invalid aggregation response payload: null.");
            }


            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                for (int i = 0; i < payload.Count; i++)
                {
                    if (payload[i].Type > 0x800 && payload[i].Type < 0x900)
                    {
                        writer.WriteTag(payload[i]);
                    }
                }

                return
                    new KsiSignature(new RawTag(Constants.KsiSignature.TagType, false, false,
                        ((MemoryStream)writer.BaseStream).ToArray()));
            }
        }
    }
}