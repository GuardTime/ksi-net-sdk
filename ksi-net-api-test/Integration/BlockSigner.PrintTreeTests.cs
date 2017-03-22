/*nameof(KsiServiceTestCases))]
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

using System;
using System.Collections.Generic;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Service;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public partial class BlockSignerTests
    {
        /// <summary>
        /// Test building Merkle trees
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerMakeTreeTest(KsiService ksiService)
        {
            Random random = new Random();

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];

                BlockSigner blockSigner = new BlockSigner(ksiService);

                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);

                    blockSigner.AddDocument(hasher.GetHash(), buffer[0] % 2 == 0 ? metadata : null);
                }

                Console.WriteLine("Document count: " + k);
                Console.WriteLine("Tree: " + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
            }
        }

        /// <summary>
        /// Test building Merkle trees with blinding masks
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerWithBlindingMasksMakeTreeTest(KsiService ksiService)
        {
            Random random = new Random();

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];

                BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);
                    blockSigner.AddDocument(hasher.GetHash(), metadata);
                }

                Console.WriteLine("Document count: " + k);
                Console.WriteLine("Tree: " + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
            }
        }

        /// <summary>
        /// Test printing tree with 11 elements
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerPrintTree11Element7MetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:48092EF
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:F7AFBCE
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                               \
                                          3L:418D6EB                                                                                      3R:318D0F3                                                                                      3R:7C8F6F0
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:58515B2                                      2R:B0C5D9B                                      2L:B11BCD9                                      2R:A2E9319                                      2L:450CA0B
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \
      1L:833EDDA                                      1L:DAB08DC              1R:B641272              1L:B162883                                                              1R:CA39D3D              1L:14BF310                                      1R:71974A8
        /    \           \                              /    \                  /    \                  /    \           \                                          /           /    \                  /    \           \                              /    \
0L:09A9FE4  0R:M:7E010  0R:BEC84E1              0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0L:BB95E9B  0R:M:7E010  0R:7943B1F                          0L:23C4ADE  0L:A360BBA  0R:M:7E010  0L:0347A3E  0R:M:7E010  0R:78C6303              0L:0579A77  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerPrintTree5Element2MetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                          4R:CC98D64
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:C4BF544
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:58515B2
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \                                               \
      1L:833EDDA                                      1R:FE982D0                                      1R:B162883
        /    \           \                              /    \                                          /    \
0L:09A9FE4  0R:M:7E010  0R:BEC84E1              0L:C734EEF  0R:B0CF0A7                          0L:BB95E9B  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerPrintTree5Element3MetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                          4R:8C4C794
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:D7556F7
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:D60EFD6                                      2R:B0C5D9B
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                              1R:6C55357              1L:DAB08DC              1R:B641272
                    /           /    \                  /    \                  /    \           \
            0L:09A9FE4  0L:BEC84E1  0R:M:7E010  0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0R:BB95E9B
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerPrintTree5ElementWithMetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                          4R:5FD0F16
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:3007670
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:CB29563                                      2R:B0C5D9B
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \
      1L:833EDDA              1R:6C55357              1L:DAB08DC              1R:B641272              1R:B162883
        /    \                  /    \                  /    \                  /    \                  /    \
0L:09A9FE4  0R:M:7E010  0L:BEC84E1  0R:M:7E010  0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0L:BB95E9B  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerPrintTree5ElementNoMetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService);

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                          3R:6AB11F0
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:64597A5
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
      1L:19E76A9              1R:FE982D0
        /    \                  /    \           \
0L:09A9FE4  0R:BEC84E1  0L:C734EEF  0R:B0CF0A7  0R:BB95E9B
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 11 elements with blindign masks
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree11Element8MetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                                                                                                                                                                                                                          6R:3EE418F
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                          5L:30765F0
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                               \
                                                                                          4L:FFDA10D                                                                                                                                                                                      4R:8CEEC90                                                                                                                                                                                      4R:BFF7E21
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:C90F283                                                                                      3R:29A8004                                                                                      3L:7836708                                                                                                                                                                                      3L:E73D2C7
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \
                  2L:A8CE49A                                                                                      2L:6B7C978                                      2R:173C33F                                      2L:D537A91                                      2R:850A763                                      2R:C6F2F05                                                                                      2L:1DB30F2                                      2R:C608215                                      2R:CA4EE44
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
      1L:4526CE6              1R:833EDDA              1R:14AE01B                                      1L:8E7123B              1R:DAB08DC              1L:0518C1E              1R:B641272              1L:C0249D2              1R:B162883              1L:0341422              1R:5219A57              1L:2AB7CC6              1R:4008D6E                                                              1L:FDE71A5              1R:14BF310              1L:748BC6B              1R:6FE689E              1L:DA0101F              1R:71974A8
                                /    \                  /    \                                                                  /    \                                          /    \                                          /    \                                          /    \                  /    \                  /    \                                                                                          /    \                                          /    \                                          /    \
                        0L:09A9FE4  0R:M:7E010  0L:CCBE4C3  0R:BEC84E1                                                  0L:C734EEF  0R:M:7E010                          0L:B0CF0A7  0R:M:7E010                          0L:BB95E9B  0R:M:7E010                          0L:7943B1F  0R:M:7E010  0L:139480D  0R:23C4ADE  0L:892771A  0R:A360BBA                                                                          0L:0347A3E  0R:M:7E010                          0L:78C6303  0R:M:7E010                          0L:0579A77  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5ElementAllMetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:3D70E30
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:274892C
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:35136F9                                                                                      3R:DA14B49
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \
                  2L:A8CE49A                                      2R:8A85301                                      2L:097523F                                      2R:173C33F                                      2R:D537A91
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
      1L:4526CE6              1R:833EDDA              1L:CCBE4C3              1R:6C55357              1L:E8C8085              1R:DAB08DC              1L:0518C1E              1R:B641272              1L:C0249D2              1R:B162883
                                /    \                                          /    \                                          /    \                                          /    \                                          /    \
                        0L:09A9FE4  0R:M:7E010                          0L:BEC84E1  0R:M:7E010                          0L:C734EEF  0R:M:7E010                          0L:B0CF0A7  0R:M:7E010                          0L:BB95E9B  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5ElementNoMetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                          4R:DECB112
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:1A493F8
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:8848F9C                                      2R:892B6CD
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \
      1L:1B13646              1R:2805ACE              1L:7884FD1              1R:F40A668              1R:1C60773
        /    \                  /    \                  /    \                  /    \                  /    \
0L:4526CE6  0R:09A9FE4  0L:18EF136  0R:BEC84E1  0L:8E7123B  0R:C734EEF  0L:7637A80  0R:B0CF0A7  0L:A1F7F24  0R:BB95E9B
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5Element3MetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:413866A
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:639AFCC
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:C90F283                                                                                      3R:C6D6F2D
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \
                  2L:A8CE49A                                                                                                                                      2R:55AA865                                      2R:D537A91
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \                                                                              /                       / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
      1L:4526CE6              1R:833EDDA              1R:14AE01B                                                              1L:7884FD1              1L:7637A80              1R:B641272              1L:C0249D2              1R:B162883
                                /    \                  /    \                                                                  /    \                                          /    \                                          /    \
                        0L:09A9FE4  0R:M:7E010  0L:CCBE4C3  0R:BEC84E1                                                  0L:8E7123B  0R:C734EEF                          0L:B0CF0A7  0R:M:7E010                          0L:BB95E9B  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5Element2MetadataTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:4C94881
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:3E6E156
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:C972494                                                                                      3R:DA14B49
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                  2R:F42B3E7                                      2L:097523F                                      2R:173C33F
                                      /                       / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \
                              1L:1B13646              1L:18EF136              1R:6C55357              1L:E8C8085              1R:DAB08DC              1L:0518C1E              1R:B641272              1R:86F6E0D
                                /    \                                          /    \                                          /    \                                          /    \                  /    \
                        0L:4526CE6  0R:09A9FE4                          0L:BEC84E1  0R:M:7E010                          0L:C734EEF  0R:M:7E010                          0L:B0CF0A7  0R:M:7E010  0L:C0249D2  0R:BB95E9B
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithLevelPrintTreeTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(HttpKsiService);
            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01180192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("012D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0134F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01480192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new DataHash(Base16.Decode("015D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
                new DataHash(Base16.Decode("0164F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC3")),
                new DataHash(Base16.Decode("0174F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC4"))
            };

            List<uint> levels = new List<uint>() { 3, 2, 0, 0, 1, 2, 0 };
            List<bool> hasMetadata = new List<bool>() { false, false, true, true, false, true, true };
            int i = 0;

            foreach (DataHash hash in hashes)
            {
                blockSigner.AddDocument(hash, hasMetadata[i] ? metadata : null, levels[i++]);
            }

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");

            Assert.AreEqual(
                @"
                                                                                                                                                                                                                                                                                                                                                                                          6R:890A256
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                          5L:6214508                                                                                                                                                                                                                                                                                                                                                                                      5R:B2CC099
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:42E567D                                                                                                                                                                                                                                                                                                                                                                                      4L:400EA80
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                                                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:180192B                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      3R:70900D9
                                                                                                                   \                                                                                                                                               \                                                                                                                                                                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                  2R:2D982C6                                                                                                                                      2R:F684F7E                                                                                                                                                                                                                                      2L:64F9189                                      2R:M:7E010
                                                                                                                                                                                                                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                              /                                                                                                                                        \
                                                                                                                                                                                                                                                      1L:F48C5E8              1R:3133FD9                                                                                                                                                              1L:5D982C6                                                                                                                                      1R:5C4B620
                                                                                                                                                                                                                                                        /    \                  /    \                                                                                                                                                                                                                                                                                                                  /    \
                                                                                                                                                                                                                                                0L:34F9189  0R:M:7E010  0L:480192B  0R:M:7E010                                                                                                                                                                                                                                                                                                  0L:74F9189  0R:M:7E010
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithLevelAndBlindingMaskPrintTreeTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(HttpKsiService, true, new byte[] { 1, 2, 3 });
            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01180192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("012D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0134F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01480192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new DataHash(Base16.Decode("015D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32"))
            };

            List<uint> levels = new List<uint>() { 3, 2, 0, 0, 1 };
            List<bool> hasMetadata = new List<bool>() { false, true, true, false, false };
            int i = 0;
            foreach (DataHash hash in hashes)
            {
                blockSigner.AddDocument(hash, hasMetadata[i] ? metadata : null, levels[i++]);
            }

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");

            Assert.AreEqual(
                @"
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          7R:ED23F1C
                                                                                                                                                                                                                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                                                                                                                                                                                                                          6L:3A445BC
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                          5L:88D662C
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:6CBBACB                                                                                                                                                                                      4R:9F9C6DC
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                               \
                                          3L:3A69728                                                                                      3R:180192B                                                                                      3L:2074482                                                                                      3R:70DBBF5                                                                                                                                                                                      3R:CE1F6C2
                                                                                                                                                                                                                                                                                                                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                                                                               \
                                                                                                                                                                                                                                                                                                                  2L:2D982C6                                      2R:M:7E010                                                                                                                                      2L:0BBA522                                                                                                                                                                                                                                                                                      2R:35BE8A6
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \                                                                                                                                                                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      1L:605B2E1              1R:F48C5E8              1R:F021289                                                                                                                                                                                                                                      1L:1B059D4              1R:5D982C6
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                /    \                  /    \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0L:34F9189  0R:M:7E010  0L:EBE7800  0R:480192B
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Get root node test
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerGetRootNodeTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Assert.AreEqual("5R:4C948816F3C4D21FF9C5CE299948DAB85F9E78585B103E13C09F053029C4758C", blockSigner.GetRootNode().ToString(), "Invalid root node");
        }

        /// <summary>
        /// Get root node test when no documents added
        /// </summary>
        /// <param name="ksiService"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void BlockSignerGetRootNodeNoDocumentsTest(KsiService ksiService)
        {
            BlockSigner blockSigner = new BlockSigner(ksiService, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            Assert.AreEqual(null, blockSigner.GetRootNode(), "Invalid root node");
        }
    }
}