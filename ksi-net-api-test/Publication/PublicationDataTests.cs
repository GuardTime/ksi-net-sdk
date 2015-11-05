using System.IO;
using NUnit.Framework;

namespace Guardtime.KSI.Publication
{
    [TestFixture]
    public class PublicationDataTest
    {
        [Test]
        public void TestPublicationDataFromTag()
        {
            using (
                var stream = new FileStream("resources/publication/publicationdata/publicationdata.tlv", FileMode.Open))
            {
                var data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);
                //                new PublicationData(data);
            }
        }

        //        [Test]
        //        public void TestPublicationDataCreate()
        //        {
        //            Stream stream = new MemoryStream();
        //            var writer = new TlvWriter(stream);
        //
        //            writer.WriteTag(new RawTag(0x2, false, false, new byte[] {0x0, 0x1}));
        //            writer.WriteTag(new RawTag(0x3, false, false, new byte[] {0x0, 0x1, 0x2, 0x5}));
        //            writer.WriteTag(new RawTag(0x4, false, false, new DataHash(HashAlgorithm.Sha2256, new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }).Imprint));
        //
        //            var data = ((MemoryStream)stream).ToArray();
        //            stream.SetLength(0);
        //
        //            stream = new FileStream("resources/publication/publicationData/missingtag.tlv", FileMode.CreateNew);
        //            writer = new TlvWriter(stream);
        //
        //            writer.WriteTag(new RawTag(0x10, false, false, data));
        //
        //
        //        }
    }
}