// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package audittrust

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// W22-07: the audit archive file. Rows older than the retention window
// are exported here BEFORE they are deleted from the live log, so the
// format has to prove two things to a later reader without the server:
// the file is intact (a hash chain over every record, so editing or
// dropping one line breaks every hash after it) and it is the file the
// hub wrote (an Ed25519-signed Merkle checkpoint over the archived
// leaves, stored separately in audit_archives as the trust anchor).
//
// Layout is JSON Lines: one header, N records, one trailer.

// ArchiveVersion is bumped on any incompatible change to the layout.
const ArchiveVersion = 1

// ArchiveHeader opens the file. PrevHash is the chain head of the
// previous archive ("" for the first), linking successive archives into
// one chain so a whole archive cannot be silently removed or reordered.
type ArchiveHeader struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	BeforeTS  string `json:"before_ts"`
	PrevHash  string `json:"prev_hash"`
}

// ArchiveRecord is one archived audit row. Hash is the hex SHA-256 chain
// link over the previous hash, the canonical leaf bytes and the entry
// bytes exactly as stored in the file.
type ArchiveRecord struct {
	Entry json.RawMessage `json:"entry"`
	Hash  string          `json:"hash"`
}

// ArchiveTrailer closes the file and carries the signed checkpoint.
// FirstID and LastID are the smallest and largest row id in the file
// (rows are archived in timestamp order, which need not be id order); the
// delete step is bounded by them.
type ArchiveTrailer struct {
	Count      int              `json:"count"`
	FirstID    int64            `json:"first_id"`
	LastID     int64            `json:"last_id"`
	ChainHead  string           `json:"chain_head"`
	Checkpoint SignedCheckpoint `json:"checkpoint"`
}

// archiveLine is the on-disk envelope; exactly one field is set per line.
type archiveLine struct {
	Header  *ArchiveHeader  `json:"header,omitempty"`
	Record  *ArchiveRecord  `json:"record,omitempty"`
	Trailer *ArchiveTrailer `json:"trailer,omitempty"`
}

// ErrArchiveEmpty is returned by Close when no record was written: an
// archive with nothing in it would have nothing to checkpoint.
var ErrArchiveEmpty = errors.New("archive has no records")

// LeafFunc maps one archived entry to the exact bytes hashed into the
// Merkle tree (the server's canonical audit leaf).
type LeafFunc func(entry []byte) ([]byte, error)

func chainHash(prev string, leaf, entry []byte) string {
	h := sha256.New()
	// NUL separators make the three fields unambiguous: without them,
	// bytes could migrate between adjacent fields and keep the same hash.
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write(leaf)
	h.Write([]byte{0})
	h.Write(entry)
	return hex.EncodeToString(h.Sum(nil))
}

// ArchiveWriter streams records to w. It holds only the hash chain and
// the 32-byte leaf hashes in memory, never the rows.
type ArchiveWriter struct {
	w       io.Writer
	hdr     ArchiveHeader
	leaf    LeafFunc
	priv    ed25519.PrivateKey
	log     MerkleLog
	chain   string
	count   int
	firstID int64
	lastID  int64
	started bool
	err     error
}

// NewArchiveWriter does no I/O: the header is written with the first
// record (or on Close), so the constructor needs no error return.
func NewArchiveWriter(w io.Writer, h ArchiveHeader, leaf LeafFunc, priv ed25519.PrivateKey) *ArchiveWriter {
	if h.Version == 0 {
		h.Version = ArchiveVersion
	}
	return &ArchiveWriter{w: w, hdr: h, leaf: leaf, priv: priv, chain: h.PrevHash}
}

func (a *ArchiveWriter) writeLine(l archiveLine) error {
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = a.w.Write(append(raw, '\n'))
	return err
}

func (a *ArchiveWriter) start() error {
	if a.started {
		return a.err
	}
	a.started = true
	a.err = a.writeLine(archiveLine{Header: &a.hdr})
	return a.err
}

// Write appends one entry to the file and the chain.
func (a *ArchiveWriter) Write(entry json.RawMessage) error {
	if err := a.start(); err != nil {
		return err
	}
	var id struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(entry, &id); err != nil {
		a.err = fmt.Errorf("archive entry: %w", err)
		return a.err
	}
	leaf, err := a.leaf(entry)
	if err != nil {
		a.err = fmt.Errorf("archive leaf: %w", err)
		return a.err
	}
	a.chain = chainHash(a.chain, leaf, entry)
	a.log.Append(leaf)
	if a.count == 0 || id.ID < a.firstID {
		a.firstID = id.ID
	}
	if id.ID > a.lastID {
		a.lastID = id.ID
	}
	a.count++
	a.err = a.writeLine(archiveLine{Record: &ArchiveRecord{Entry: entry, Hash: a.chain}})
	return a.err
}

// Close writes the trailer with the signed checkpoint over every leaf.
func (a *ArchiveWriter) Close() (ArchiveTrailer, error) {
	if err := a.start(); err != nil {
		return ArchiveTrailer{}, err
	}
	if a.count == 0 {
		return ArchiveTrailer{}, ErrArchiveEmpty
	}
	t := ArchiveTrailer{
		Count: a.count, FirstID: a.firstID, LastID: a.lastID,
		ChainHead: a.chain, Checkpoint: a.log.SignCheckpoint(a.priv),
	}
	if err := a.writeLine(archiveLine{Trailer: &t}); err != nil {
		return ArchiveTrailer{}, err
	}
	return t, nil
}

// ScanArchive verifies a whole archive and calls visit for each entry in
// order. Verification can only finish at the trailer, so a caller that
// must not act on unverified data scans once with a nil visit and then
// again to consume; visit may therefore see entries from a file that
// later turns out to be bad, and its caller must roll back on error.
func ScanArchive(r io.Reader, pub ed25519.PublicKey, leaf LeafFunc, visit func(json.RawMessage) error) (ArchiveHeader, ArchiveTrailer, error) {
	var (
		hdr   ArchiveHeader
		trl   ArchiveTrailer
		log   MerkleLog
		br    = bufio.NewReader(r)
		chain string
		count int
		first int64
		last  int64
		line  = 0
		done  bool
	)
	for {
		raw, rerr := br.ReadBytes('\n')
		if len(bytes.TrimSpace(raw)) > 0 {
			line++
			var l archiveLine
			if err := json.Unmarshal(raw, &l); err != nil {
				return hdr, trl, fmt.Errorf("archive line %d: %w", line, err)
			}
			if done {
				return hdr, trl, errors.New("archive has data after the trailer")
			}
			switch {
			case l.Header != nil && line == 1:
				hdr = *l.Header
				if hdr.Version != ArchiveVersion {
					return hdr, trl, fmt.Errorf("unsupported archive version %d", hdr.Version)
				}
				chain = hdr.PrevHash
			case l.Record != nil && line > 1:
				lf, err := leaf(l.Record.Entry)
				if err != nil {
					return hdr, trl, fmt.Errorf("archive line %d: %w", line, err)
				}
				chain = chainHash(chain, lf, l.Record.Entry)
				if chain != l.Record.Hash {
					return hdr, trl, fmt.Errorf("archive hash chain broken at line %d", line)
				}
				var id struct {
					ID int64 `json:"id"`
				}
				if err := json.Unmarshal(l.Record.Entry, &id); err != nil {
					return hdr, trl, fmt.Errorf("archive line %d: %w", line, err)
				}
				if count == 0 || id.ID < first {
					first = id.ID
				}
				if id.ID > last {
					last = id.ID
				}
				count++
				log.Append(lf)
				if visit != nil {
					if err := visit(l.Record.Entry); err != nil {
						return hdr, trl, err
					}
				}
			case l.Trailer != nil && line > 1:
				trl = *l.Trailer
				done = true
			default:
				return hdr, trl, fmt.Errorf("archive line %d is out of place", line)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return hdr, trl, rerr
		}
	}
	if !done {
		return hdr, trl, errors.New("archive is truncated: no trailer")
	}
	if trl.Count != count || trl.FirstID != first || trl.LastID != last {
		return hdr, trl, fmt.Errorf("archive trailer disagrees with its records (count %d vs %d)", trl.Count, count)
	}
	if trl.ChainHead != chain {
		return hdr, trl, errors.New("archive chain head does not match its records")
	}
	root, err := VerifyCheckpoint(pub, trl.Checkpoint)
	if err != nil {
		return hdr, trl, err
	}
	if trl.Checkpoint.Size != count || !EqualRoots(root, log.Root()) {
		return hdr, trl, errors.New("archive checkpoint does not match its records")
	}
	return hdr, trl, nil
}

// ReadArchive verifies and returns every entry. It holds the whole file in
// memory; large archives should use ScanArchive.
func ReadArchive(r io.Reader, pub ed25519.PublicKey, leaf LeafFunc) (ArchiveHeader, []json.RawMessage, ArchiveTrailer, error) {
	var entries []json.RawMessage
	h, t, err := ScanArchive(r, pub, leaf, func(e json.RawMessage) error {
		entries = append(entries, append(json.RawMessage(nil), e...))
		return nil
	})
	if err != nil {
		return h, nil, t, err
	}
	return h, entries, t, nil
}
