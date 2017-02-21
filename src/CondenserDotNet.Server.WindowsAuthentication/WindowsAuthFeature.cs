using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using static Interop.Secur32;

namespace CondenserDotNet.Server.WindowsAuthentication
{
    public class WindowsAuthFeature : IDisposable
    {
        private SecurityHandle _context;

        public WindowsIdentity Identity { get; set; }
        
        public void Dispose()
        {
            Identity?.Dispose();
            if(_context.IsValid())
            {
                FreeCredentialsHandle(_context);
                _context = new SecurityHandle(0);
            }
            Identity = null;
        }

        internal object GetChallengeToken()
        {
            throw new NotImplementedException();
        }
    }
}
