using System.Security.Cryptography;

namespace Bolt
{

    internal sealed class AesCounterModeProvider : CounterModeProviderBase
    {
        protected override SymmetricAlgorithm CreateCryptoProvider()
        {
            return new AesCryptoServiceProvider();
        }
    }

}
