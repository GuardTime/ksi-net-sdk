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
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Specialized reader for decoding TLV data.
    /// </summary>
    public class TlvReader : BinaryReader
    {
        /// <summary>
        ///     Reads from given input stream for TLV data.
        /// </summary>
        /// <param name="input">input stream to read data from</param>
        public TlvReader(Stream input) : base(input)
        {
        }

        /// <summary>
        ///     Reads a complete TLV item from the wrapped stream.
        /// </summary>
        /// <returns>raw tlv tag</returns>
        public TlvTag ReadTag()
        {
            try
            {
                byte firstByte = ReadByte();

                bool tlv16 = (firstByte & Constants.Tlv.Tlv16Flag) != 0;
                bool nonCritical = (firstByte & Constants.Tlv.NonCriticalFlag) != 0;
                bool forward = (firstByte & Constants.Tlv.ForwardFlag) != 0;

                uint type = (uint)(firstByte & Constants.Tlv.TypeMask);
                ushort length;

                if (tlv16)
                {
                    byte typeLsb = ReadByte();
                    type = (type << Constants.BitsInByte) | typeLsb;
                    length = (ushort)((ReadByte() << Constants.BitsInByte) | ReadByte());
                }
                else
                {
                    length = ReadByte();
                }

                byte[] data = new byte[length];
                int bytesRead = Read(data, 0, length);

                if (bytesRead != length)
                {
                    throw new TlvException("Could not read TLV data with expected length(" + length +
                                           "), instead could only read length(" + bytesRead + ").");
                }

                return new RawTag(type, nonCritical, forward, data);
            }
            catch (EndOfStreamException e)
            {
                throw new TlvException("Premature end of input data.", e);
            }
        }
    }
}