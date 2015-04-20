using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Util
{
    public class Util
    {
        private Util()
        {
            
        }

        public static bool IsArrayEqual<T>(T[] arr1, T[] arr2) 
        {
            if (arr1 == null || arr2 == null)
            {
                return false;
            }

            if (arr1.Length != arr2.Length)
            {
                return false;
            }

            for (var i = 0; i < arr1.Length; i++)
            {
                if (!Equals(arr1[i], arr2[i]))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
