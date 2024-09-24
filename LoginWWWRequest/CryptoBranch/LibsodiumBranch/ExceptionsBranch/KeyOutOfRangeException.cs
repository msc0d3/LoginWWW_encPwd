using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LoginWWWRequest.CryptoBranch.LibsodiumBranch.ExceptionsBranch
{
    public class KeyOutOfRangeException : ArgumentOutOfRangeException
    {
        public KeyOutOfRangeException()
        {
        }

        public KeyOutOfRangeException(string message)
          : base(message)
        {
        }

        public KeyOutOfRangeException(string message, Exception inner)
          : base(message, inner)
        {
        }

        public KeyOutOfRangeException(string paramName, object actualValue, string message)
          : base(paramName, actualValue, message)
        {
        }
    }
}
