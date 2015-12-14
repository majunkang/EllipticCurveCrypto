using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using System.Numerics;
using EllipticCurveCrypto;
using System.Diagnostics;
using System.Globalization;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace UnitTestEllipticCurveCrypto
{
    [TestClass]
    public class TestEllipticCurveCryptoProvider
    {
        [TestMethod]
        public void TestMakeKeyPair()
        {
            var provider = new EllipticCurveCryptoProvider(EllipticCurveNames.Secp256R1);

            BigInteger privateKeyAlice;
            EllipticCurvePoint publicKeyAlice;

            BigInteger privateKeyBob;
            EllipticCurvePoint publicKeyBob;

            provider.MakeKeyPair(out privateKeyAlice, out publicKeyAlice);
            provider.MakeKeyPair(out privateKeyBob, out publicKeyBob);

            EllipticCurvePoint sharedSecretAlice = provider.DeriveSharedSecret(privateKeyAlice, publicKeyBob);
            EllipticCurvePoint sharedSecretBob = provider.DeriveSharedSecret(privateKeyBob, publicKeyAlice);

            Assert.AreEqual(sharedSecretAlice.X, sharedSecretBob.X);
            Assert.AreEqual(sharedSecretAlice.Y, sharedSecretBob.Y);
        }

        [TestMethod]
        public void TestDeriveSharedSecret()
        {

            BigInteger pX = BigInteger.Parse("68319caad24e6909cd8b3962d7d0077f4cc9dc348b96da80e9b45de70e6ba30e", NumberStyles.HexNumber);
            BigInteger pY = BigInteger.Parse("00d82256dcb4153cb26b9ffc3846660b348767e06422c996b0f1646c8f1aee0051", NumberStyles.HexNumber);
            EllipticCurvePoint publicKey = new EllipticCurvePoint(pX, pY);

            BigInteger privateKey = BigInteger.Parse("00885d74025021979e140f419966b2119dc4a19f89bae719c14f97bdb594c3e2f5", NumberStyles.HexNumber);

            var provider = new EllipticCurveCryptoProvider(EllipticCurveNames.Secp256R1);
            EllipticCurvePoint sharedSecret = provider.DeriveSharedSecret(privateKey, publicKey);

            IBuffer info = CryptographicBuffer.CreateFromByteArray(new byte[] { 0x01 });
            IBuffer salt = null;
            var outputKeyMaterial = provider.DerivteKeyWithHkdf(sharedSecret, salt, info);

            var strKeyHex = CryptographicBuffer.EncodeToHexString(outputKeyMaterial);
            Assert.AreEqual("a6cf3a73f624e73bef4f9760156b039bc2004133207c1186685aa72c2cbdf752".ToUpper(), strKeyHex.ToUpper());
        }



    }
}
