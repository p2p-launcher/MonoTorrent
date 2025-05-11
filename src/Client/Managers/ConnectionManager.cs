//
// ConnectionManager.cs
//
// Authors:
//   Alan McGovern alan.mcgovern@gmail.com
//
// Copyright (C) 2006 Alan McGovern
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//


using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

using MonoTorrent.BEncoding;
using MonoTorrent.BlockReader;
using MonoTorrent.Client.RateLimiters;
using MonoTorrent.Connections;
using MonoTorrent.Connections.Peer;
using MonoTorrent.Connections.Peer.Encryption;
using MonoTorrent.Logging;
using MonoTorrent.Messages.Peer;
using MonoTorrent.Messages.Peer.FastPeer;

using ReusableTasks;

namespace MonoTorrent.Client
{
    /// <summary>
    /// Main controller class for all incoming and outgoing connections
    /// </summary>
    public class ConnectionManager
    {
        static readonly Logger logger = Logger.Create (nameof (ConnectionManager));

        struct AsyncConnectState : IEquatable<AsyncConnectState>
        {
            public AsyncConnectState (TorrentManager manager, IPeerConnection connection, ValueStopwatch timer)
            {
                Manager = manager;
                Connection = connection;
                Timer = timer;
            }

            public readonly IPeerConnection Connection;
            public readonly TorrentManager Manager;
            public readonly ValueStopwatch Timer;

            public bool Equals (AsyncConnectState other)
                => Connection == other.Connection;

            public override bool Equals ([NotNullWhen (true)] object? obj)
                => obj is AsyncConnectState other && Equals (other);

            public override int GetHashCode ()
                => Connection.GetHashCode ();
        }

        public event EventHandler<AttemptConnectionEventArgs>? BanPeer;

        HashSet<string> BannedPeerIPAddresses = new HashSet<string> ();

        internal IBlockReader BlockReader { get; }

        Factories Factories { get; }

        Dictionary<BEncodedString, int> LocalPeerIds { get; } = new Dictionary<BEncodedString, int> ();

        internal BEncodedString LocalPeerId { get; }

        IPeerConnectionGate ConnectionGate { get; set; }

        /// <summary>
        /// The number of concurrent connection attempts
        /// </summary>
        public int HalfOpenConnections => PendingConnects.Count;

        /// <summary>
        /// The maximum number of concurrent connection attempts
        /// </summary>
        internal int MaxHalfOpenConnections => Settings.MaximumHalfOpenConnections;

        /// <summary>
        /// The number of open connections
        /// </summary>
        public int OpenConnections => Torrents.Select (t => t.OpenConnections).Sum ();

        List<AsyncConnectState> PendingConnects { get; }

        internal EngineSettings Settings { get; set; }
        internal List<TorrentManager> Torrents { get; set; }

        internal ConnectionManager (BEncodedString localPeerId, EngineSettings settings, Factories factories, IBlockReader blockReader)
        {
            BlockReader = blockReader ?? throw new ArgumentNullException (nameof (blockReader));
            LocalPeerId = localPeerId ?? throw new ArgumentNullException (nameof (localPeerId));
            LocalPeerIds.Add (localPeerId, 1);
            Settings = settings ?? throw new ArgumentNullException (nameof (settings));
            Factories = factories ?? throw new ArgumentNullException (nameof (factories));

            ConnectionGate = factories.CreatePeerConnectionGate ();

            PendingConnects = new List<AsyncConnectState> ();
            Torrents = new List<TorrentManager> ();
        }

        internal void Add (TorrentManager manager)
        {
            Torrents.Add (manager);
        }

        internal void Remove (TorrentManager manager)
        {
            Torrents.Remove (manager);
        }

        async void ConnectToPeer (TorrentManager manager, Peer peer)
        {
            // Whenever we try to connect to a peer, we may try multiple times.
            //  1. If we cannot establish a connection, we bail out. A retry will occur later
            //  2. If we can establish a connection but the connection closes, retry with a different
            //     encryption method immediately. The odds are high this will succeed.
            ConnectionFailureReason? failureReason;
            try {
                manager.Peers.ConnectingToPeers.Add (peer);
                failureReason = await DoConnectToPeer (manager, peer);
            } catch {
                failureReason = ConnectionFailureReason.Unknown;
            } finally {
                manager.Peers.ConnectingToPeers.Remove (peer);
            }

            // Always restart the the timer after the connection attempt completes
            peer.WaitUntilNextConnectionAttempt.Restart ();

            // If the connection attempt failed, decide what to do next. Drop the peer or retry it later.
            if (failureReason.HasValue) {
                peer.FailedConnectionAttempts++;

                // If we have not exhausted all retry attempts, add the peer back for subsequent retry
                if (failureReason.Value != ConnectionFailureReason.ConnectedToSelf &&
                    Settings.GetConnectionRetryDelay (peer.FailedConnectionAttempts).HasValue)
                    manager.Peers.AvailablePeers.Add (peer);

                manager.RaiseConnectionAttemptFailed (new ConnectionAttemptFailedEventArgs (peer.Info, failureReason.Value, manager));
            }

            // Always try to connect to a new peer. If there are no active torrents, the call will just bail out.
            TryConnect ();
        }

        async ReusableTask<ConnectionFailureReason?> DoConnectToPeer (TorrentManager manager, Peer peer)
        {
            ConnectionFailureReason? latestResult = ConnectionFailureReason.Unknown;
            foreach (var allowedEncryption in Settings.OutgoingConnectionEncryptionTiers) {
                // Bail out if the manager can no longer accept connections (i.e. is in the Stopping or Stopped mode now)
                if (!manager.Mode.CanAcceptConnections)
                    return ConnectionFailureReason.Unknown;

                // Create a new IPeerConnection object for each connection attempt.
                var connection = Factories.CreatePeerConnection (peer.Info.ConnectionUri);
                if (connection == null)
                    return ConnectionFailureReason.UnknownUriSchema;

                var state = new AsyncConnectState (manager, connection, ValueStopwatch.StartNew ());
                try {
                    PendingConnects.Add (state);

                    // A return value of 'null' means connection succeeded
                    latestResult = await DoConnectToPeer (manager, peer, connection, allowedEncryption);
                    if (latestResult == null)
                        return null;
                } catch {
                    latestResult = ConnectionFailureReason.Unknown;
                } finally {
                    PendingConnects.Remove (state);
                }

                // If the connection did not succeed, dispose the object and try again with a different encryption tier.
                connection.SafeDispose ();

                // If the error is *not* a retryable error, then bail out and return the failure.
                // Otherwise loop and try again. A failure to send/receive a handshake is considered to be
                // an encryption negiotiation failure as for outgoing connections the local client may send a
                // plaintext handshake and the remote client may discard it as it only accepts encrypted ones.
                if (latestResult != ConnectionFailureReason.EncryptionNegiotiationFailed)
                    return latestResult;
            }

            // if we got non-null failure reasons, return the most recent one here.
            return latestResult;
        }

        async ReusableTask<ConnectionFailureReason?> DoConnectToPeer (TorrentManager manager, Peer peer, IPeerConnection connection, IList<EncryptionType> allowedEncryption)
        {
            try {
                await NetworkIO.ConnectAsync (connection);
            } catch {
                // A failure to connect is unlikely to be fixed by retrying a different encryption method, so bail out immediately.
                return ConnectionFailureReason.Unreachable;
            }

            // If the torrent is no longer downloading/seeding etc, bail out.
            if (manager.Disposed || !manager.Mode.CanAcceptConnections)
                return ConnectionFailureReason.Unknown;

            // If too many connections are open, bail out.
            if (OpenConnections > Settings.MaximumConnections || manager.OpenConnections > manager.Settings.MaximumConnections)
                return ConnectionFailureReason.TooManyOpenConnections;

            // Reset the connection timer so there's a little bit of extra time for the handshake.
            // Otherwise, if this fails we should probably retry with a different encryption type.
            try {
                return await ProcessNewOutgoingConnection (manager, peer, connection, allowedEncryption);
            } catch (Exception e) {
                logger.Error ($"Unable to connect to {connection.Uri}: {e.Message}");
                logger.Debug ($"{e}");
                return ConnectionFailureReason.Unknown;
            }
        }

        internal bool Contains (TorrentManager manager)
        {
            return Torrents.Contains (manager);
        }

        internal async ReusableTask<ConnectionFailureReason?> ProcessNewOutgoingConnection (TorrentManager manager, Peer peer, IPeerConnection connection, IList<EncryptionType> allowedEncryption)
        {
            BEncodedString connectAs = await Factories.CreateTemporaryLocalPeerIdAsync (manager, LocalPeerId, peer.Info.PeerId, manager.InfoHashes.V1OrV2, connection.Uri);
            if ((connectAs is null || connectAs.Span.Length != 20) && connectAs != LocalPeerId) {
                logger.Exception (
                    new ArgumentException ("Peer ID must be exactly 20 bytes long", paramName: "temporaryLocalPeerId"),
                    "Generated temporary peer ID was not 20 bytes long");
                return ConnectionFailureReason.Unknown;
            }
            if (!LocalPeerId.Equals (connectAs))
                lock (LocalPeerIds)
                    LocalPeerIds[connectAs] = LocalPeerIds.TryGetValue (connectAs, out int repeats) ? repeats + 1 : 1;

            var bitfield = new BitField (manager.Bitfield.Length);

            IEncryption decryptor;
            IEncryption encryptor;

            HandshakeMessage handshake;
            try {
                // If this is a hybrid torrent and a connection is being made with the v1 infohash, then
                // set the bit which tells the peer the connection can be upgraded to a bittorrent v2 (BEP52) connection.
                var canUpgradeToV2 = manager.InfoHashes.IsHybrid;

                // Create a handshake message to send to the peer
                handshake = new HandshakeMessage (manager.InfoHashes.V1OrV2.Truncate (), connectAs, Constants.ProtocolStringV100, enableFastPeer: true, enableExtended: true, supportsUpgradeToV2: canUpgradeToV2);
                logger.InfoFormatted (connection, "Sending handshake message with peer id '{0}'", connectAs);

                EncryptorFactory.EncryptorResult result = await EncryptorFactory.CheckOutgoingConnectionAsync (connection, allowedEncryption, manager.InfoHashes.V1OrV2.Truncate (), handshake, Factories, Settings.ConnectionTimeout);
                decryptor = result.Decryptor;
                encryptor = result.Encryptor;

                // If plaintext encryption is used, we need to *receive* the remote handshake before we can confirm
                // that negotiation has completed successfully.
                handshake = await PeerIO.ReceiveHandshakeAsync (connection, decryptor);
                logger.InfoFormatted(connection, "[outgoing] Received handshake message with peer id '{0}'", handshake.PeerId);
                if (!await ConnectionGate.TryAcceptHandshakeAsync(LocalPeerId, peer.Info, connection, manager.InfoHashes.V1OrV2))
                {
                    logger.InfoFormatted(connection, "[outgoing] Handshake with peer_id '{0}' rejected by the connection gate", peer.Info.PeerId);
                    throw new TorrentException("Handshake rejected by the connection gate");
                }
                if (handshake.ProtocolString != Constants.ProtocolStringV100)
                    logger.Info (connection, "Received handshake but protocol was unsupported");
            } catch {
                if (!LocalPeerId.Equals(connectAs))
                    lock (LocalPeerIds)
                        LocalPeerIds[connectAs] = LocalPeerIds[connectAs] - 1;
                logger.Info (connection, "Could not receive a handshake from the peer");
                return ConnectionFailureReason.EncryptionNegiotiationFailed;
            }

            PeerId id;
            try {
                // Receive their handshake. NOTE: For hybrid torrents the standard is to send the V1 infohash
                // and if the peer responds with the V2 infohash, treat the connection as a V2 connection. The
                // biggest (only?) difference is that it means we can request the merkle tree layer hashes from
                // peers who support v2.
                id = CreatePeerIdFromHandshake (handshake, peer, connection, manager, encryptor: encryptor, decryptor: decryptor);
                logger.InfoFormatted (id.Connection, "Received handshake message with peer id '{0}'", handshake.PeerId);

                if (IsSelf (handshake.PeerId))
                    return ConnectionFailureReason.ConnectedToSelf;

                // CreatePeerIdFromHandshake files in the peerid, which is important context for whether or not
                // the peer connection should be closed.
                if (ShouldBanPeer (peer.Info, AttemptConnectionStage.HandshakeComplete)) {
                    logger.Debug ($"Not connecting to {connection.Uri} as it is banned");
                    return ConnectionFailureReason.Banned;
                }
            } catch (Exception e) {
                if (!LocalPeerId.Equals(connectAs))
                    lock (LocalPeerIds)
                        LocalPeerIds[connectAs] = LocalPeerIds[connectAs] - 1;
                logger.Debug ($"handshake with {connection.Uri} failed: {e.Message}");
                return ConnectionFailureReason.HandshakeFailed;
            }

            if (!LocalPeerId.Equals (connectAs))
                lock (LocalPeerIds)
                    LocalPeerIds[connectAs] = LocalPeerIds[connectAs] - 1;

            try {
                if (id.BitField.Length != manager.Bitfield.Length)
                    throw new TorrentException ($"The peer's bitfield was of length {id.BitField.Length} but the TorrentManager's bitfield was of length {manager.Bitfield.Length}.");

                manager.Peers.ActivePeers.Add (peer);
                manager.Peers.ConnectedPeers.Add (id);

                manager.Mode.HandlePeerConnected (id);
                id.MessageQueue.SetReady ();
                TryProcessQueue (manager, id);

                id.Peer.FailedConnectionAttempts = 0;

                ReceiveMessagesAsync (id.Connection, id.Decryptor, manager.DownloadLimiters, id.Monitor, manager, id);

                id.WhenConnected.Restart ();
                id.LastBlockReceived.Reset ();
                return null;
            } catch (Exception e) {
                logger.Debug ($"outgoing connection to {connection.Uri} failed: {e.Message}");
                manager.RaiseConnectionAttemptFailed (new ConnectionAttemptFailedEventArgs (id.Peer.Info, ConnectionFailureReason.Unknown, manager));
                CleanupSocket (manager, id, DisconnectReason.GeneralOutgoingConnectionFailure);
                return ConnectionFailureReason.Unknown;
            }
        }

        internal static PeerId CreatePeerIdFromHandshake (HandshakeMessage handshake, Peer peer, IPeerConnection connection, TorrentManager manager, IEncryption encryptor, IEncryption decryptor)
        {
            if (!handshake.ProtocolString.Equals (Constants.ProtocolStringV100)) {
                logger.InfoFormatted (connection, "Invalid protocol in handshake: {0}", handshake.ProtocolString);
                throw new ProtocolException ("Invalid protocol string");
            }

            // If the infohash doesn't match, dump the connection
            if (!manager.InfoHashes.Contains (handshake.InfoHash)) {
                logger.Info (connection, "HandShake.Handle - Invalid infohash");
                throw new TorrentException ("Invalid infohash. Not tracking this torrent");
            }

            // If we got the peer as a "compact" peer, then the peerid will be empty. In this case
            // we just copy the one that is in the handshake.
            if (BEncodedString.IsNullOrEmpty (peer.Info.PeerId))
                peer.UpdatePeerId (handshake.PeerId);

            // If this is a hybrid torrent, and the other peer announced with the v1 hash *and* set the bit which indicates
            // they can upgrade to a V2 connection, respond with the V2 hash to upgrade the connection to V2 mode.
            var infoHash = handshake.SupportsUpgradeToV2 && manager.InfoHashes.IsHybrid ? manager.InfoHashes.V2! : manager.InfoHashes.Expand (handshake.InfoHash);

            // Create the peerid now that everything is established.
            var id = new PeerId (peer, connection, new BitField (manager.Bitfield.Length), infoHash, encryptor: encryptor, decryptor: decryptor, new Software (handshake.PeerId));

            // If the peer id's don't match, dump the connection. This is due to peers faking usually
            if (!id.Peer.Info.PeerId.Equals (handshake.PeerId)) {
                if (manager.Settings.RequirePeerIdToMatch) {
                    // Several prominent clients randomise peer ids (at the least, everything based on libtorrent)
                    // so closing connections when the peer id does not match risks blocking compatibility with many
                    // clients. Additionally, MonoTorrent has long been configured to default to compact tracker responses
                    // so the odds of having the peer ID are slim.
                    logger.InfoFormatted (id.Connection, "HandShake.Handle - Invalid peerid. Expected '{0}' but received '{1}'", id.Peer.Info.PeerId, handshake.PeerId);
                    throw new TorrentException ("Supplied PeerID didn't match the one the tracker gave us");
                } else {
                    // We don't care about the mismatch for public torrents. uTorrent randomizes its PeerId, as do other clients.
                    id.Peer.UpdatePeerId (handshake.PeerId);
                }
            }
            // Copy over the capability bits
            id.SupportsFastPeer = handshake.SupportsFastPeer;
            id.SupportsLTMessages = handshake.SupportsExtendedMessaging;

            // reset the timers so the connection isn't closed early due to inactivity
            id.LastMessageReceived.Restart ();
            id.LastMessageSent.Restart ();


            // If they support fast peers, create their list of allowed pieces that they can request off me
            if (id.SupportsFastPeer && id.AddressBytes.Length > 0 && manager != null && manager.HasMetadata) {
                lock (AllowedFastHasher)
                    id.AmAllowedFastPieces = AllowedFastAlgorithm.Calculate (AllowedFastHasher, id.AddressBytes.Span, manager.InfoHashes, (uint) manager.Torrent!.PieceCount);
            }
            return id;
        }
        static readonly SHA1 AllowedFastHasher = SHA1.Create ();

        internal async void ReceiveMessagesAsync (IPeerConnection connection, IEncryption decryptor, RateLimiterGroup downloadLimiter, ConnectionMonitor monitor, TorrentManager torrentManager, PeerId id)
        {
            await MainLoop.SwitchToThreadpool ();

            Memory<byte> currentBuffer = default;

            Memory<byte> smallBuffer = default;
            ByteBufferPool.Releaser smallReleaser = default;

            Memory<byte> largeBuffer = default;
            ByteBufferPool.Releaser largeReleaser = default;
            ValueStopwatch stopwatch = ValueStopwatch.StartNew ();
            TimeSpan? receiveTime = null, handleTime = null;
            try {
                while (true) {
                    if (id.AmRequestingPiecesCount == 0) {
                        if (!largeBuffer.IsEmpty) {
                            largeReleaser.Dispose ();
                            largeReleaser = default;
                            largeBuffer = currentBuffer = default;
                        }
                        if (smallBuffer.IsEmpty) {
                            smallReleaser = NetworkIO.BufferPool.Rent (ByteBufferPool.SmallMessageBufferSize, out smallBuffer);
                            currentBuffer = smallBuffer;
                        }
                    } else {
                        if (!smallBuffer.IsEmpty) {
                            smallReleaser.Dispose ();
                            smallReleaser = default;
                            smallBuffer = currentBuffer = default;
                        }
                        if (largeBuffer.IsEmpty) {
                            largeReleaser = NetworkIO.BufferPool.Rent (ByteBufferPool.LargeMessageBufferSize, out largeBuffer);
                            currentBuffer = largeBuffer;
                        }
                    }

                    receiveTime = handleTime = null;
                    stopwatch.Restart ();
                    (PeerMessage message, PeerMessage.Releaser releaser) = await PeerIO.ReceiveMessageAsync (connection, decryptor, downloadLimiter, monitor, torrentManager.Monitor, torrentManager, currentBuffer).ConfigureAwait (false);
                    receiveTime = stopwatch.Elapsed;
                    stopwatch.Restart ();
                    HandleReceivedMessage (id, torrentManager, message, releaser);
                    handleTime = stopwatch.Elapsed;
                }
            } catch (Exception e) {
                logger.Error ($"Peer {id.Uri} receiver loop stopped due to error: {e.Message}");
                logger.Debug ($"{e}");
                await ClientEngine.MainLoop;
                CleanupSocket (torrentManager, id, DisconnectReason.ReceiverLoopError);
            } finally {
                smallReleaser.Dispose ();
                largeReleaser.Dispose ();
            }
        }

        static async void HandleReceivedMessage (PeerId id, TorrentManager torrentManager, PeerMessage message, PeerMessage.Releaser releaser = default)
        {
            await ClientEngine.MainLoop;

            if (!id.Disposed) {
                id.LastMessageReceived.Restart ();
                try {
                    torrentManager.Mode.HandleMessage (id, message, releaser);
                } catch (Exception ex) {
                    logger.Exception (ex, "Unexpected error handling a message from a peer");
                    torrentManager.Engine!.ConnectionManager.CleanupSocket (torrentManager, id, DisconnectReason.InternalMessageHandlingError);
                }
            } else {
                releaser.Dispose ();
            }
        }

        internal void CleanupSocket (TorrentManager manager, PeerId id, DisconnectReason reason)
        {
            // We might dispose the socket from an async send *and* an async receive call.
            if (id.Disposed)
                return;

            try {
                manager.PieceManager.CancelRequests (id);
                if (!id.AmChoking)
                    manager.UploadingTo--;
                manager.Peers.ConnectedPeers.Remove (id);
                id.Peer.CleanedUpCount++;
                id.Peer.WaitUntilNextConnectionAttempt.Restart ();

                logger.Info (id.Connection, "Closing connection");
                // We can reuse this peer if the connection says so and it's not marked as inactive
                bool canReuse = (id.Connection.CanReconnect)
                    && !manager.InactivePeerManager.InactivePeerList.Contains (id.Peer.Info.ConnectionUri)
                    && !manager.Engine!.PeerId.Equals (id.Peer.Info.PeerId)
                    && Settings.GetConnectionRetryDelay (id.Peer.FailedConnectionAttempts).HasValue;

                manager.Peers.ActivePeers.Remove (id.Peer);

                // If we get our own details, this check makes sure we don't try connecting to ourselves again
                if (canReuse && !IsSelf (id.Peer.Info.PeerId)) {
                    if (!manager.Peers.AvailablePeers.Contains(id.Peer) && id.Peer.CleanedUpCount < 5)
                        manager.Peers.AvailablePeers.Add(id.Peer);
                    else if (id.Peer.CleanedUpCount >= 5)
                    {
                        logger.Debug($"banned {id.Peer.Info.ConnectionUri.Host} as we had to disconnect from it 5 times");
                        BannedPeerIPAddresses.Add(id.Peer.Info.ConnectionUri.Host);
                    }
                }
            } catch (Exception ex) {
                logger.Exception (ex, "An unexpected error occured cleaning up a connection");
            } finally {
                id.Dispose ();
            }
            try {
                manager.Mode.HandlePeerDisconnected (id, reason);
            } catch (Exception ex) {
                logger.Exception (ex, "An unexpected error occured calling HandlePeerDisconnected");
            }
        }

        bool IsSelf (BEncodedString peerId)
        {
            lock (LocalPeerIds)
                return LocalPeerIds.ContainsKey (peerId);
        }

        /// <summary>
        /// Cancel all pending connection attempts which have exceeded <see cref="EngineSettings.ConnectionTimeout"/>
        /// </summary>
        internal void CancelPendingConnects ()
        {
            CancelPendingConnects (null);
        }

        /// <summary>
        /// Cancel all pending connection for the given <see cref="TorrentManager"/>, or which have exceeded <see cref="EngineSettings.ConnectionTimeout"/>
        /// </summary>
        internal void CancelPendingConnects (TorrentManager? manager)
        {
            foreach (AsyncConnectState pending in PendingConnects)
                if (pending.Manager == manager || pending.Timer.Elapsed > Settings.ConnectionTimeout)
                    pending.Connection.Dispose ();
        }

        /// <summary>
        /// This method is called when the ClientEngine recieves a valid incoming connection
        /// </summary>
        /// <param name="manager">The torrent which the peer is associated with.</param>
        /// <param name="id">The peer who just conencted</param>
        internal async ReusableTask<bool> IncomingConnectionAcceptedAsync (TorrentManager manager, PeerId id)
        {
            try {
                bool maxAlreadyOpen = OpenConnections >= Settings.MaximumConnections
                    || manager.OpenConnections >= manager.Settings.MaximumConnections;

                if (manager.Peers.ActivePeers.Contains (id.Peer)) {
                    logger.Debug ($"{id.Connection}: Already connected to peer");
                    id.Connection.Dispose ();
                    return false;
                }
                if (maxAlreadyOpen) {
                    logger.Debug ($"Connected to too many peers - disconnecting");
                    CleanupSocket (manager, id, DisconnectReason.MaximumConnectionsExceeded);
                    return false;
                }
                if (ShouldBanPeer (id.Peer.Info, AttemptConnectionStage.HandshakeComplete)) {
                    logger.Info (id.Connection, "Peer was banned");
                    CleanupSocket (manager, id, DisconnectReason.Ban);
                    return false;
                }


                // Send our handshake first, then decide if we've connected to ourselves or not.
                var handshake = new HandshakeMessage (id.ExpectedInfoHash.Truncate (), LocalPeerId, Constants.ProtocolStringV100);
                await PeerIO.SendMessageAsync (id.Connection, id.Encryptor, handshake, manager.UploadLimiters, id.Monitor, manager.Monitor);

                if (LocalPeerId.Equals (id.PeerID)) {
                    logger.Info ("Connected to self - disconnecting");
                    CleanupSocket (manager, id, DisconnectReason.Self);
                    return false;
                }

                // Add the PeerId to the lists *before* doing anything asynchronous. This ensures that
                // all PeerIds are tracked in 'ConnectedPeers' as soon as they're created.
                manager.Peers.AvailablePeers.Remove (id.Peer);
                manager.Peers.ActivePeers.Add (id.Peer);
                manager.Peers.ConnectedPeers.Add (id);

                id.WhenConnected.Restart ();
                // Baseline the time the last block was received
                id.LastBlockReceived.Reset ();

                manager.Mode.HandlePeerConnected (id);
                id.MessageQueue.SetReady ();
                TryProcessQueue (manager, id);

                // We've sent our handshake so begin our looping to receive incoming message
                ReceiveMessagesAsync (id.Connection, id.Decryptor, manager.DownloadLimiters, id.Monitor, manager, id);
                logger.Info (id.Connection, $"connection to {manager.LogName} fully accepted");
                return true;
            } catch (Exception ex) {
                logger.Exception (ex, "Error handling incoming connection");
                CleanupSocket (manager, id, DisconnectReason.GeneralIncomingConnectionFailure);
                return false;
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="manager">The torrent which the peer is associated with.</param>
        /// <param name="id">The peer whose message queue you want to start processing</param>
        internal async void TryProcessQueue (TorrentManager manager, PeerId id)
        {
            if (!id.MessageQueue.BeginProcessing ())
                return;

            await MainLoop.SwitchToThreadpool ();

            ByteBufferPool.Releaser socketMemoryReleaser = default;
            Memory<byte> socketMemory = default;

            try {
                while (id.MessageQueue.TryDequeue (out PeerMessage? msg, out PeerMessage.Releaser msgReleaser)) {
                    using var autorelease = msgReleaser;

                    if (socketMemory.IsEmpty || socketMemory.Length < msg.ByteLength) {
                        socketMemoryReleaser.Dispose ();
                        socketMemoryReleaser = NetworkIO.BufferPool.Rent (msg.ByteLength, out socketMemory);
                    }

                    var buffer = socketMemory.Slice (0, msg.ByteLength);
                    if (msg is PieceMessage pm) {
                        async ReusableTask Reject ()
                        {
                            if (id.SupportsFastPeer) {
                                var reject = new RejectRequestMessage (pm);
                                logger.Debug ($"Rejected {pm.PieceIndex} to {id.Uri} because we don't have it");
                                await PeerIO.SendMessageAsync (id.Connection, id.Encryptor, reject, manager.UploadLimiters, id.Monitor, manager.Monitor, buffer).ConfigureAwait (false);
                            } else {
                                var bitfieldUpdate = new BitfieldMessage (manager.Bitfield);
                                logger.Debug ($"Rejected {pm.PieceIndex} to {id.Uri} because we don't have it. Will send the bitfield.");
                                await PeerIO.SendMessageAsync (id.Connection, id.Encryptor, bitfieldUpdate, manager.UploadLimiters, id.Monitor, manager.Monitor, buffer).ConfigureAwait (false);
                            }
                        }

                        if (!manager.Bitfield[pm.PieceIndex]) {
                            await Reject ().ConfigureAwait(false);
                            continue;
                        }

                        pm.SetData ((default, buffer.Slice (buffer.Length - pm.RequestLength)));
                        try {
                            var request = new BlockInfo (pm.PieceIndex, pm.StartOffset, pm.RequestLength);
                            int read = await BlockReader.ReadAsync (manager, request, pm.Data).ConfigureAwait (false);
                            if (read < 0) {
                                logger.Debug ($"{pm.PieceIndex} is not available anymore");
                                await Reject ().ConfigureAwait (false);
                                await ClientEngine.MainLoop;
                                manager.UpdatePieceHashStatus (pm.PieceIndex, hashPassed: false,
                                    hashed: 1, totalHashing: 1);
                                continue;
                            }
                        } catch (Exception ex) {
                            await ClientEngine.MainLoop;
                            manager.TrySetError (Reason.ReadFailure, ex);
                            return;
                        }
                        Interlocked.Increment (ref id.piecesSent);
                    }

                    await PeerIO.SendMessageAsync (id.Connection, id.Encryptor, msg, manager.UploadLimiters, id.Monitor, manager.Monitor, buffer).ConfigureAwait (false);
                    if (msg is PieceMessage)
                        Interlocked.Decrement (ref id.isRequestingPiecesCount);

                    id.LastMessageSent.Restart ();
                }
            } catch (Exception e) {
                logger.InfoFormatted ("Peer {0} queue processing stopped due to error: {1}", id.Uri, e);
                await ClientEngine.MainLoop;
                CleanupSocket (manager, id, DisconnectReason.MessageQueueProcessingError);
            } finally {
                socketMemoryReleaser.Dispose ();
            }
        }


        internal bool ShouldBanPeer (PeerInfo peer, AttemptConnectionStage stage)
        {
            if (BannedPeerIPAddresses.Count > 0 && BannedPeerIPAddresses.Contains (peer.ConnectionUri.Host))
                return true;

            if (BanPeer == null)
                return false;

            var e = new AttemptConnectionEventArgs (peer, stage);
            BanPeer (this, e);
            if (e.BanPeer) {
                BannedPeerIPAddresses.Add (peer.ConnectionUri.Host);
                logger.Debug ($"Banned {peer.ConnectionUri.Host} at {stage}");
            }
            return e.BanPeer;
        }

        static readonly Comparison<TorrentManager> ActiveConnectionsComparer = (left, right)
            => (left.Peers.ConnectedPeers.Count + left.Peers.ConnectingToPeers.Count).CompareTo (right.Peers.ConnectedPeers.Count + right.Peers.ConnectingToPeers.Count);

        internal void TryConnect ()
        {
            if (!Settings.AllowOutgoingConnections)
                return;

            // If we have already reached our max connections globally, don't try to connect to a new peer
            while (OpenConnections <= Settings.MaximumConnections && PendingConnects.Count <= MaxHalfOpenConnections) {
                Torrents.Sort (ActiveConnectionsComparer);

                bool connected = false;
                for (int i = 0; i < Torrents.Count; i++) {
                    // If we successfully connect, then break out of this loop and restart our
                    // connection process from the first node in the list again.
                    if (TryConnect (Torrents[i])) {
                        connected = true;
                        break;
                    }
                }

                // If we failed to connect to anyone after walking the entire list, give up for now.
                if (!connected)
                    break;
            }
        }

        static readonly TimeSpan minimumTimeBetweenOpportunisticUnbans = TimeSpan.FromSeconds (30);
        DateTimeOffset lastUnban = DateTimeOffset.UtcNow;
        bool TryConnect (TorrentManager manager)
        {
            // If the torrent isn't active, don't connect to a peer for it
            if (!manager.Mode.CanAcceptConnections)
                return false;

            // If we have reached the max peers allowed for this torrent, don't connect to a new peer for this torrent
            if ((manager.Peers.ConnectedPeers.Count + manager.Peers.ConnectingToPeers.Count) >= manager.Settings.MaximumConnections) {
                logger.Debug ($"Enough connections for {manager.LogName}");
                return false;
            }

            var peer = manager.Peers.AvailablePeers.FirstOrDefault (p => manager.Mode.ShouldConnect(p) == DisconnectReason.None);

            var unbanDelay = peer is null
                ? minimumTimeBetweenOpportunisticUnbans
                : TimeSpan.FromTicks(8 * minimumTimeBetweenOpportunisticUnbans.Ticks);
            if (manager.Peers.ConnectedPeers.Count == 0 && DateTimeOffset.UtcNow - lastUnban > unbanDelay) {
                var banlist = BannedPeerIPAddresses.ToArray ();
                if (banlist.Length > 0) {
                    int index = new Random ().Next (banlist.Length);
                    string unban =  banlist[index];
                    logger.Debug ($"Unbanning {unban} for {manager.LogName}: we don't have any other peers to connect to");
                    lastUnban = DateTimeOffset.UtcNow;
                    BannedPeerIPAddresses.Remove (unban);
                }
            }

            // If this is true, there were no peers in the available list to connect to.
            if (peer is null) {
                string reasons = string.Join(Environment.NewLine,
                    manager.Peers.AvailablePeers
                           .Select(p => $"{p.Info.ConnectionUri} - {manager.Mode.ShouldConnect(p)}"));
                logger.Debug ($"No peers available for {manager.LogName}:\n{reasons}");

                return false;
            }

            // Remove the peer from the lists so we can start connecting to him
            manager.Peers.AvailablePeers.Remove (peer);

            if (ShouldBanPeer (peer.Info, AttemptConnectionStage.BeforeConnectionEstablished)) {
                logger.Debug ($"Not connecting to {peer.Info.PeerId} as it is banned");
                return false;
            }

            // Connect to the peer
            logger.InfoFormatted ("Trying to connect {0} to {1}", manager.LogName, peer.Info.ConnectionUri);
            ConnectToPeer (manager, peer);
            return true;
        }
    }
}
