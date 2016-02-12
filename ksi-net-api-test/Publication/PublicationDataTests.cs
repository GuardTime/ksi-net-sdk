/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */
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
                FileStream stream = new FileStream("resources/publication/publicationdata/publicationdata.tlv", FileMode.Open))
            {
                byte[] data = new byte[stream.Length];
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