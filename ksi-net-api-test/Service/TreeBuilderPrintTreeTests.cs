/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class TreeBuilderPrintTreeTests
    {
        [Test]
        public void TreeBuilderInvalidMaxHeight()
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(delegate
            {
                TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default, 256);
            });

            Assert.AreEqual("maxTreeHeight", ex.ParamName);
        }

        [Test]
        public void TreeBuilderAddNull()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                builder.AddNode(null);
            });

            Assert.AreEqual("node", ex.ParamName);
        }

        /// <summary>
        /// Test printing tree with 11 elements
        /// </summary>
        [Test]
        public void TreeBuilderPrintTree11Element7MetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382"))), metadata);

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:314E3C6
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:CAE40AB
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:418D6EB                                                                                      3R:831F8B4
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \
                  2L:58515B2                                      2R:B0C5D9B                                      2L:E34C621                                      2R:67DDE73                                      2R:11D8C00
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
      1L:833EDDA                                      1L:DAB08DC              1R:B641272              1L:B162883              1R:6294F5C              1L:CA39D3D              1R:14BF310                                      1R:71974A8
        /    \           \                              /    \                  /    \                  /    \                  /    \                  /    \                  /    \                              /           /    \
0L:09A9FE4  0R:M:7E010  0R:BEC84E1              0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0L:BB95E9B  0R:M:7E010  0L:7943B1F  0R:23C4ADE  0L:A360BBA  0R:M:7E010  0L:0347A3E  0R:M:7E010              0L:78C6303  0L:0579A77  0R:M:7E010
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        [Test]
        public void TreeBuilderPrintTree5Element2MetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), metadata);

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                          3R:E94A02E
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:FB1FC80                                      2R:AA2D875
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
      1L:833EDDA              1R:1431ECD                                      1R:B162883
        /    \                  /    \                              /           /    \
0L:09A9FE4  0R:M:7E010  0L:BEC84E1  0R:C734EEF              0L:B0CF0A7  0L:BB95E9B  0R:M:7E010
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        [Test]
        public void TreeBuilderPrintTree5Element3MetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
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
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        [Test]
        public void TreeBuilderPrintTree5ElementWithMetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), metadata);

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
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
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        [Test]
        public void TreeBuilderPrintTree5ElementNoMetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
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
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 11 elements with blindign masks
        /// </summary>
        [Test]
        public void TreeBuilderWithBlindingMasksPrintTree11Element8MetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), null,
                new TreeNode(new DataHash(Base16.Decode("0118EF13609A9FE4304273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("018E7123B09A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("017637A8009A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("01A1F7F2409A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("012CDD00E09A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902"))), null,
                new TreeNode(new DataHash(Base16.Decode("01C50121509A9FE4304273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF"))), null,
                new TreeNode(new DataHash(Base16.Decode("01892771A09A9FE4304273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("01FDE71A509A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("017950AA809A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("01AD7936409A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                                                                                                                                                                                                                          6R:A8A9130
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                          5L:64A935C
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:8815ADE                                                                                                                                                                                      4R:173B1BF
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                               \
                                          3L:ECD02D8                                                                                      3R:4487D29                                                                                      3L:EFEFF49                                                                                      3R:B33A539                                                                                      3R:3579285
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:43961A5                                                                                      2L:B623DDD                                      2R:CF15D19                                      2L:C9DF749                                      2R:4D84D22                                      2L:ED618EC                                      2R:04EB25B                                      2L:9C2470D                                      2R:FF8B6E1
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                              1R:833EDDA              1R:0C656A0                                                              1R:DAB08DC                                      1R:B641272                                      1R:B162883                                      1R:5219A57              1L:3517953              1R:A1A015B                                      1R:14BF310                                      1R:6FE689E                                      1R:71974A8
                    /           /    \                  /    \                                                      /           /    \                              /           /    \                              /           /    \                              /           /    \                  /    \                  /    \                              /           /    \                              /           /    \                              /           /    \
            0L:4526CE6  0L:09A9FE4  0R:M:7E010  0L:18EF136  0R:BEC84E1                                      0L:8E7123B  0L:C734EEF  0R:M:7E010              0L:7637A80  0L:B0CF0A7  0R:M:7E010              0L:A1F7F24  0L:BB95E9B  0R:M:7E010              0L:2CDD00E  0L:7943B1F  0R:M:7E010  0L:C501215  0R:23C4ADE  0L:892771A  0R:A360BBA              0L:FDE71A5  0L:0347A3E  0R:M:7E010              0L:7950AA8  0L:78C6303  0R:M:7E010              0L:AD79364  0L:0579A77  0R:M:7E010
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        [Test]
        public void TreeBuilderWithBlindingMasksPrintTree5ElementAllMetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:320FAA2
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:DC6BCEC
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:F2C9F3F                                                                                      3R:03AD090
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \
                  2L:43961A5                                      2R:BFD0336                                      2L:ACCAD49                                      2R:3709C82                                      2R:64CBF48
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                              1R:833EDDA                                      1R:6C55357                                      1R:DAB08DC                                      1R:B641272                                      1R:B162883
                    /           /    \                              /           /    \                              /           /    \                              /           /    \                              /           /    \
            0L:4526CE6  0L:09A9FE4  0R:M:7E010              0L:4526CE6  0L:BEC84E1  0R:M:7E010              0L:4526CE6  0L:C734EEF  0R:M:7E010              0L:4526CE6  0L:B0CF0A7  0R:M:7E010              0L:4526CE6  0L:BB95E9B  0R:M:7E010
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        [Test]
        public void TreeBuilderWithBlindingMasksPrintTree5ElementNoMetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                                                                          4R:636585F
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:60F31AF
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:0879E3A                                      2R:946BCEC
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \
      1L:E2EB833              1R:84AAC49              1L:1661ECB              1R:A060514              1R:B081606
        /    \                  /    \                  /    \                  /    \                  /    \
0L:4526CE6  0R:09A9FE4  0L:4526CE6  0R:BEC84E1  0L:4526CE6  0R:C734EEF  0L:4526CE6  0R:B0CF0A7  0L:4526CE6  0R:BB95E9B
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        [Test]
        public void TreeBuilderWithBlindingMasksPrintTree5Element3MetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                                                                          4R:24BC20C
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:9A394AF                                                                                      3R:5E043F8
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:43961A5                                      2R:BE4203B                                      2L:3709C82                                      2R:64CBF48
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                              1R:833EDDA              1L:84AAC49              1R:1661ECB                                      1R:B641272                                      1R:B162883
                    /           /    \                  /    \                  /    \                              /           /    \                              /           /    \
            0L:4526CE6  0L:09A9FE4  0R:M:7E010  0L:4526CE6  0R:BEC84E1  0L:4526CE6  0R:C734EEF              0L:4526CE6  0L:B0CF0A7  0R:M:7E010              0L:4526CE6  0L:BB95E9B  0R:M:7E010
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        [Test]
        public void TreeBuilderWithBlindingMasksPrintTree5Element2MetadataTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))), null,
                new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:5596B29
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:A5B5332
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:00AA7DE                                                                                      3R:03AD090
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                  2R:BFD0336                                      2L:ACCAD49                                      2R:3709C82
                                      /                       / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \
                              1L:E2EB833                                      1R:6C55357                                      1R:DAB08DC                                      1R:B641272              1R:B081606
                                /    \                              /           /    \                              /           /    \                              /           /    \                  /    \
                        0L:4526CE6  0R:09A9FE4              0L:4526CE6  0L:BEC84E1  0R:M:7E010              0L:4526CE6  0L:C734EEF  0R:M:7E010              0L:4526CE6  0L:B0CF0A7  0R:M:7E010  0L:4526CE6  0R:BB95E9B
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        [Test]
        public void TreeBuilderWithLevel6Element2PrintTreeTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);
            IdentityMetadata metadata = new IdentityMetadata("test client id");

            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01180192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("012D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0134F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01480192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new DataHash(Base16.Decode("015D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
                new DataHash(Base16.Decode("0164F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC3")),
            };

            List<uint> levels = new List<uint>() { 3, 2, 0, 0, 1, 2 };
            List<bool> hasMetadata = new List<bool>() { false, false, true, false, false, true };
            int i = 0;

            foreach (DataHash hash in hashes)
            {
                builder.AddNode(new TreeNode(hash, levels[i]), hasMetadata[i] ? metadata : null);
                i++;
            }

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");

            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:63AD3A8
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:58943B1                                                                                                                                                                                      4R:400EA80
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                          3L:180192B                                                                                      3R:24CB462                                                                                                                                                                                      3R:70900D9
                                                                                                                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                  2L:2D982C6                                      2R:6D0E0CF                                                                                                                                      2L:64F9189                                      2R:M:7E010
                                                                                                                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                              /
                                                                                                                                                      1L:F48C5E8                                                                                      1L:5D982C6
                                                                                                                                                        /    \           \
                                                                                                                                                0L:34F9189  0R:M:7E010  0R:480192B
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        [Test]
        public void TreeBuilderWithLevelPrintTree5ElementTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01180192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("012D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0134F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01480192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new DataHash(Base16.Decode("015D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
            };

            List<uint> levels = new List<uint>() { 2, 0, 0, 0, 0 };
            int i = 0;

            foreach (DataHash hash in hashes)
            {
                builder.AddNode(new TreeNode(hash, levels[i++]));
            }

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");

            Assert.AreEqual(
                @"
                                          3R:174C6C7
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                  2L:180192B                                      2R:6088218
                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                      1L:E734B9E              1R:E5FF17C
                                                        /    \                  /    \
                                                0L:2D982C6  0R:34F9189  0L:480192B  0R:5D982C6
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        [Test]
        public void TreeBuilderWithLevelPrintTree4ElementTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01180192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("012D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0134F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01480192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
            };

            List<uint> levels = new List<uint>() { 4, 0, 0, 0 };
            int i = 0;

            foreach (DataHash hash in hashes)
            {
                builder.AddNode(new TreeNode(hash, levels[i++]));
            }

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");

            Assert.AreEqual(
                @"
                                                                                                                                                                                          5R:1CDE80F
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                          4L:180192B

                                          
                                                                                                                                                                                                                   \
                                                                                                                                                                                                                  2R:97690AF
                                                                                                                                                                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                                      1L:E734B9E
                                                                                                                                                                                                        /    \           \
                                                                                                                                                                                                0L:2D982C6  0R:34F9189  0R:480192B
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        [Test]
        public void TreeBuilderWithLevelAndBlindingMaskPrintTreeTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);
            IdentityMetadata metadata = new IdentityMetadata("test client id");

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
                builder.AddNode(new TreeNode(hash, levels[i]), hasMetadata[i] ? metadata : null,
                    new TreeNode(new DataHash(Base16.Decode("014526CE609A9FD8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
                i++;
            }

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");

            Assert.AreEqual(
                @"
                                                                                                                                                                                                                                                                                                                                                                                          6R:3859802
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                          5L:D5FC272
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                               \
                                                                                          4L:24111E7                                                                                                                                                                                      4R:880D593                                                                                                                                                                                      4R:3F7A4E4
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                          3R:180192B                                                                                                                                                                                      3R:70DBBF5                                                                                      3L:7A534DC
                                                                                                                                                                                                                                                                                                                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \
                                                                                                                                                                                                                                                                                                                  2L:2D982C6                                      2R:M:7E010                                      2L:D93035B                                                                                      2R:A847F38
                                                                                                                                                                                                                                                                                                                                                                                                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                                                                                                                                                                                                                                                                                                                                                                                                                              1R:F48C5E8              1R:BA3FCC5                                                              1R:5D982C6
                                                                    /                                                                                                                                                                                               /                                                                                                                                               /           /    \                  /    \                                                      /
                                                            0L:4526CE6                                                                                                                                                                                      0L:4526CE6                                                                                                                                      0L:4526CE6  0L:34F9189  0R:M:7E010  0L:4526CE6  0R:480192B                                      0L:4526CE6
",
                TreeVisualizer.PrintTree(builder.GetTreeRoot()));
        }

        /// <summary>
        /// Get root node test
        /// </summary>
        [Test]
        public void TreeBuilderGetRootNodeTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853"))));
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD"))), metadata);
            builder.AddNode(new TreeNode(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA"))));

            Console.WriteLine("Tree: \"" + TreeVisualizer.PrintTree(builder.GetTreeRoot()) + "\"");
            Assert.AreEqual("4R:8C4C7941FFE2473773D0C6A26889D9C3B7A4A973A639D49C50C5E5B4A8827F68", builder.GetTreeRoot().ToString(), "Invalid root node");
        }

        /// <summary>
        /// Get root node test when no hashes added
        /// </summary>
        [Test]
        public void TreeBuilderGetRootNodeNoHashesTest()
        {
            TreeBuilder builder = new TreeBuilder(HashAlgorithm.Default);

            Assert.AreEqual(null, builder.GetTreeRoot(), "Invalid root node");
        }
    }
}