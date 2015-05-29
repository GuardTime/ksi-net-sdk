using System;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class KsiSignatureDoTests
    {
        [Test]
        public void GetMemberTest()
        {
            using (var stream = new FileStream("resources/signature/signature-ok.tlv", FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                var tag = reader.ReadTag();
                var test = new KsiSignatureDo(tag);
                try
                {
                    test.IsValidStructure();
                }
                catch (InvalidTlvStructureException e)
                {
                    Console.WriteLine(e);
                    Console.WriteLine(e.GetTlvTagTrace());
                }

                var time = Environment.TickCount;
                var i = 0;
                
                while (Environment.TickCount - time < 1000)
                {
                    test = new KsiSignatureDo(tag);
                    i++;
                }
                Console.WriteLine(i);
                Console.WriteLine(test);
            }

        }
    }
}