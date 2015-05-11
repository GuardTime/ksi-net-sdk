using System;
using System.IO;
using Guardtime.KSI.Parser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Publication
{
    [TestClass]
    public class PublicationsFileDoTests
    {

        [TestMethod]
        public void TestPublicationFileFromFile()
        {
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                var data = new byte[stream.Length - 8];
                stream.Read(new byte[8], 0, 8);
                stream.Read(data, 0, (int) stream.Length - 8);
//                var tag = new PublicationsFileDo(new RawTag(0x0, false, false, data));
//                tag.DecodeValue(data);
//                Console.WriteLine(tag);
            }

                

        }


    }
}
