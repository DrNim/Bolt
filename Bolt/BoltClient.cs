using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Bolt
{
    public sealed class BoltClient : BoltBase
    {

        public override void Initialize()
        {
            if (TrustedIssuers == null)
            {
                throw new NullReferenceException(string.Format("{0} is null.", nameof(TrustedIssuers)));
            }

            if (MutualAuthenticationRequired && LocalTag == null)
            {
                throw new NullReferenceException(string.Format("{0} is null.", nameof(LocalTag)));
            }

            BufferFrame(new ClientNegotiateFrame(), FrameState.ClientNegotiate);
            SendNegotiateFrame();
        }

        internal override void OnFrameProcessed(BaseFrame frame)
        {
            switch (State)
            {
                case FrameState.ClientNegotiate:
                    HandleNegotiateFrame((ClientNegotiateFrame)frame);
                    break;
                case FrameState.ClientExchange:
                    HandleExchangeFrame((ClientExchangeFrame)frame);
                    break;
                case FrameState.ClientEcho:
                    HandleEchoFrame((ClientEchoFrame)frame);
                    break;
            }
        }

        private void HandleNegotiateFrame(ClientNegotiateFrame frame)
        {
            if (frame.MinVersion > MAX_VERSION || frame.MaxVersion < MIN_VERSION)
            {
                OnExceptionThrown(new InvalidDataException("Invalid protocol version."));
                return;
            }

            if (frame.Difficulty > MAX_DIFFICULTY)
            {
                OnExceptionThrown(new InvalidDataException("Challenge difficulty is too high."));
                return;
            }

            if (frame.IsMutual && LocalTag == null)
            {
                OnExceptionThrown(new InvalidOperationException("Server requires mutual authentication."));
                return;
            }

            HashPuzzle puzzle = new HashPuzzle(HashAlgorithmName.SHA256, frame.Difficulty, frame.Nonce);
            bool success = puzzle.FindSolution();

            if (success)
            {
                Version = Math.Min(frame.MaxVersion, MAX_VERSION);
                ServerNonce = frame.Nonce;
                ClientNonce = CreateNonce(NONCE_LENGTH);

                BufferFrame(new ClientExchangeFrame(), FrameState.ClientExchange);
            }
            else
            {
                BufferFrame(new ClientNegotiateFrame(), FrameState.ClientNegotiate);
            }

            SendExchangeFrame(success, puzzle.Solution);
        }

        private void HandleExchangeFrame(ClientExchangeFrame frame)
        {
            if (frame.Tag.Length > MAX_TAG_LENGTH)
            {
                OnExceptionThrown(new InvalidDataException("Invalid tag length."));
                return;
            }

            if (MutualAuthenticationRequired && !frame.IsMutual)
            {
                OnExceptionThrown(new InvalidDataException("Server authentication failed."));
                return;
            }

            Tag remoteTag = Tag.Deserialize(frame.Tag);

            if (!remoteTag.Verify(TrustedIssuers))
            {
                OnExceptionThrown(new InvalidDataException("Invalid tag."));
                return;
            }

            IsMutuallyAuthenticated = frame.IsMutual;

            List<byte[]> signatureParts = new List<byte[]>();
            signatureParts.Add(frame.PublicKey);
            signatureParts.Add(ClientNonce);
            signatureParts.Add(new byte[] { frame.IsMutual ? (byte)1 : (byte)0 });

            if (IsMutuallyAuthenticated)
            {
                signatureParts.Add(LocalTag.RawData);
            }

            if (!VerifyData(remoteTag.Holder.Key, frame.Signature, signatureParts.ToArray()))
            {
                OnExceptionThrown(new InvalidDataException("Invalid signature."));
                return;
            }

            SendValidateFrame(GetPublicKey(), remoteTag);
            InitializeCrypto(frame.PublicKey, false);

            ClientNonce = CreateNonce(NONCE_LENGTH);

            BufferFrame(new ClientEchoFrame(), FrameState.ClientEcho);
            SendEchoFrame(ClientNonce);
        }

        private void HandleEchoFrame(ClientEchoFrame frame)
        {
            if (!CompareBytes(frame.ClientNonce, 0, ClientNonce, 0, ClientNonce.Length))
            {
                OnExceptionThrown(new InvalidDataException("Nonce echo failed."));
                return;
            }

            ServerNonce = frame.ServerNonce;
            SendEchoFrame(ServerNonce);

            Establish();
        }

        private void SendNegotiateFrame()
        {
            ServerNegotiateFrame frame = new ServerNegotiateFrame();
            frame.MinVersion = MIN_VERSION;
            frame.MaxVersion = MAX_VERSION;

            SendFrame(frame);
        }

        private void SendExchangeFrame(bool success, byte[] solution)
        {
            ServerExchangeFrame frame = new ServerExchangeFrame();
            frame.Success = success;
            frame.Solution = solution;
            frame.Nonce = ClientNonce;
            frame.Tag = LocalTag?.RawData;

            SendFrame(frame);
        }

        private void SendValidateFrame(byte[] publicKey, Tag remoteTag)
        {
            byte[] signature = null;

            if (IsMutuallyAuthenticated)
            {
                List<byte[]> signatureParts = new List<byte[]>();
                signatureParts.Add(publicKey);
                signatureParts.Add(ServerNonce);
                signatureParts.Add(remoteTag.RawData);

                signature = SignData(LocalTag.Holder.Key, signatureParts.ToArray());
            }

            ServerValidateFrame frame = new ServerValidateFrame();
            frame.PublicKey = publicKey;
            frame.Signature = signature;

            SendFrame(frame);
        }

        private void SendEchoFrame(byte[] nonce)
        {
            ServerEchoFrame frame = new ServerEchoFrame();
            frame.Nonce = nonce;

            SendFrame(frame);
        }

    }

}