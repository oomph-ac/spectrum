package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	packet2 "github.com/cooldogedev/spectrum/server/packet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// handleServer continuously reads packets from the server and forwards them to the client.
func handleServer(s *Session) {
loop:
	for {
		select {
		case <-s.ctx.Done():
			break loop
		case <-s.serverConn.Context().Done():
			if err := s.fallback(); err != nil {
				s.CloseWithError(fmt.Errorf("fallback failed: %w", err))
				logError(s, "failed to fallback to a different server", err)
				break loop
			}
		default:
		}

		server := s.Server()
		pk, err := server.ReadPacket()
		if err != nil {
			server.CloseWithError(fmt.Errorf("failed to read packet from server: %w", err))
			continue loop
		}

		switch pk := pk.(type) {
		case *packet2.Latency:
			s.latency.Store(pk.Latency)
		case *packet2.Transfer:
			if err := s.Transfer(pk.Addr); err != nil {
				logError(s, "failed to transfer", err)
			}
		case *packet2.EOBNotification:
			s.processor.ProcessEndOfBatch()
		case packet.Packet:
			ctx := NewContext()
			s.processor.ProcessServer(ctx, &pk)
			if ctx.Cancelled() {
				continue loop
			}

			if s.opts.SyncProtocol {
				for _, latest := range s.client.Proto().ConvertToLatest(pk, s.client) {
					s.tracker.handlePacket(latest)
				}
			} else {
				s.tracker.handlePacket(pk)
			}

			if err := s.client.WritePacket(pk); err != nil {
				s.CloseWithError(fmt.Errorf("failed to write packet to client: %w", err))
				logError(s, "failed to write packet to client", err)
				break loop
			}
		case []byte:
			ctx := NewContext()
			s.processor.ProcessServerEncoded(ctx, &pk)
			if ctx.Cancelled() {
				continue loop
			}

			if _, err := s.client.Write(pk); err != nil {
				s.CloseWithError(fmt.Errorf("failed to write packet to client: %w", err))
				logError(s, "failed to write packet to client", err)
				break loop
			}
		}
	}
}

// handleClient continuously reads packets from the client and forwards them to the server.
func handleClient(s *Session) {
	header := &packet.Header{}
	pool := s.client.Proto().Packets(true)
	var shieldID int32
	for _, item := range s.client.GameData().Items {
		if item.Name == "minecraft:shield" {
			shieldID = int32(item.RuntimeID)
			break
		}
	}

loop:
	for {
		select {
		case <-s.ctx.Done():
			break loop
		default:
		}

		payload, err := s.client.ReadBytes()
		if err != nil {
			s.CloseWithError(fmt.Errorf("failed to read packet from client: %w", err))
			logError(s, "failed to read packet from client", err)
			break loop
		}

		if err := handleClientPacket(s, header, pool, shieldID, payload); err != nil {
			s.Server().CloseWithError(fmt.Errorf("failed to write packet to server: %w", err))
		}
	}
}

// handleLatency periodically sends the client's current ping and timestamp to the server for latency reporting.
// The client's latency is derived from half of RakNet's round-trip time (RTT).
// To calculate the total latency, we multiply this value by 2.
func handleLatency(s *Session, interval int64) {
	ticker := time.NewTicker(time.Millisecond * time.Duration(interval))
	defer ticker.Stop()
loop:
	for {
		select {
		case <-s.ctx.Done():
			break loop
		case <-ticker.C:
			if err := s.Server().WritePacket(&packet2.Latency{Latency: s.client.Latency().Milliseconds() * 2, Timestamp: time.Now().UnixMilli()}); err != nil {
				logError(s, "failed to write latency packet", err)
			}
		}
	}
}

// handleClientPacket processes and forwards the provided packet from the client to the server.
func handleClientPacket(s *Session, header *packet.Header, pool packet.Pool, shieldID int32, payload []byte) (err error) {
	ctx := NewContext()
	buf := bytes.NewBuffer(payload)
	if err := header.Read(buf); err != nil {
		return errors.New("failed to decode header")
	}

	if !slices.Contains(s.opts.ClientDecode, header.PacketID) {
		s.processor.ProcessClientEncoded(ctx, &payload)
		if !ctx.Cancelled() {
			return s.Server().Write(payload)
		}
		return
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while decoding packet %v: %v", header.PacketID, r)
		}
	}()

	factory, ok := pool[header.PacketID]
	if !ok {
		return fmt.Errorf("unknown packet %d", header.PacketID)
	}

	pk := factory()
	pk.Marshal(s.client.Proto().NewReader(buf, shieldID, true))

	if s.opts.SyncProtocol {
		s.processor.ProcessClient(ctx, &pk)
		if !ctx.Cancelled() {
			return s.Server().WritePacket(pk)
		}
	} else {
		for _, latest := range s.client.Proto().ConvertToLatest(pk, s.client) {
			s.processor.ProcessClient(ctx, &latest)
			if ctx.Cancelled() {
				break
			}
			if err := s.Server().WritePacket(latest); err != nil {
				return err
			}
		}
	}
	return
}

func logError(s *Session, msg string, err error) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	if !errors.Is(err, context.Canceled) {
		s.logger.Error(msg, "err", err)
	}
}
