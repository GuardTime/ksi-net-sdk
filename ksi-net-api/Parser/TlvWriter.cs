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
using System.IO;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV object writer for stream.
    /// </summary>
    public class TlvWriter : BinaryWriter
    {
        /// <summary>
        ///     Create TLV object writer instance.
        /// </summary>
        /// <param name="input">Output stream</param>
        public TlvWriter(Stream input) : base(input)
        {
        }

        /// <summary>
        ///     Write TLV object to given stream.
        /// </summary>
        /// <param name="tag">TLV object</param>
        public void WriteTag(ITlvTag tag)
        {
            if (tag == null)
            {
                return;
            }

            if (tag.Type > Constants.Tlv.MaxType)
            {
                throw new ArgumentOutOfRangeException(nameof(tag));
            }

            byte[] data = tag.EncodeValue();

            bool tlv16 = ((tag as TlvTag)?.ForceTlv16Encoding ?? false)
                         || tag.Type > Constants.Tlv.TypeMask
                         || (data != null && data.Length > byte.MaxValue);
            byte firstByte = (byte)((tlv16 ? Constants.Tlv.Tlv16Flag : 0)
                                    + (tag.NonCritical ? Constants.Tlv.NonCriticalFlag : 0)
                                    + (tag.Forward ? Constants.Tlv.ForwardFlag : 0));

            if (tlv16)
            {
                firstByte = (byte)(firstByte
                                   | (tag.Type >> Constants.BitsInByte) & Constants.Tlv.TypeMask);
                Write(firstByte);
                Write((byte)tag.Type);
                if (data == null)
                {
                    Write((byte)0);
                }
                else
                {
                    if (data.Length > ushort.MaxValue)
                    {
                        throw new ArgumentOutOfRangeException(nameof(data));
                    }
                    Write((byte)(data.Length >> Constants.BitsInByte));
                    Write((byte)data.Length);
                    Write(data);
                }
            }
            else
            {
                firstByte = (byte)(firstByte | tag.Type & Constants.Tlv.TypeMask);
                Write(firstByte);
                if (data == null)
                {
                    Write((byte)0);
                }
                else
                {
                    Write((byte)data.Length);
                    Write(data);
                }
            }
        }
    }
}