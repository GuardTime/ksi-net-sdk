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

namespace Guardtime.KSI.Utils
{
    /// <summary>
    ///     Base32 converter.
    /// </summary>
    public static class Base32
    {
        private static readonly BaseX Inst = new BaseX("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", false, '=');

        /// <summary>
        ///     Encode data bytes to base32 string.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <returns>base32 string</returns>
        public static string Encode(byte[] bytes)
        {
            return Encode(bytes, 0, bytes.Length);
        }

        /// <summary>
        ///     Encode data bytes with given offset and length to base32 string.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <param name="off">data offset</param>
        /// <param name="len">data length</param>
        /// <returns>base32 string</returns>
        public static string Encode(byte[] bytes, int off, int len)
        {
            return bytes == null ? null : Inst.Encode(bytes, off, len, null, 0);
        }

        /// <summary>
        ///     Decode base32 string to byte array.
        /// </summary>
        /// <param name="s">base32 string</param>
        /// <returns>base32 bytes</returns>
        public static byte[] Decode(string s)
        {
            return s == null ? null : Inst.Decode(s);
        }
    }
}