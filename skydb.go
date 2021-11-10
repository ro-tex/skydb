/*
Package skydb provides a simple library for working with Skynet Lab's SkyDB and
the Skynet Registry on which SkyDB is built.
*/
package skydb

import (
	"bytes"
	"reflect"
	"strings"

	"github.com/ro-tex/skydb/registry"
	"gitlab.com/NebulousLabs/errors"
	"gitlab.com/SkynetLabs/skyd/node/api/client"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"gitlab.com/SkynetLabs/skyd/skymodules/renter"
	"go.sia.tech/siad/crypto"
)

var (
	// ErrNotFound is returned when an entry is not found.
	ErrNotFound = errors.New("skydb entry not found")
)

type (
	// SkyDBI is the interface for communicating with SkyDB. We use an
	// interface, so we can easily override it for testing purposes.
	SkyDBI interface {
		Read(hash crypto.Hash) ([]byte, uint64, error)
		Write(data []byte, dataKey crypto.Hash, rev uint64) error
	}

	// SkyDB is a decentralized tool for storing mutable data built on top of
	// Skynet Registry.
	//
	// See https://blog.sia.tech/skydb-a-mutable-database-for-the-decentralized-web-7170beeaa985
	SkyDB struct {
		r *registry.Registry
	}
)

// New creates a new SkyDB client with the given options.
// If the options are empty we'll look for skyd at localhost:9980, we'll use
// "Sia-Agent" as user agent, and we'll try to get the password for skyd from
// the environment.
func New(sk crypto.SecretKey, pk crypto.PublicKey, opts client.Options) (*SkyDB, error) {
	if reflect.DeepEqual(opts, client.Options{}) {
		var err error
		opts, err = client.DefaultOptions()
		if err != nil {
			return nil, errors.AddContext(err, "failed to get default client options")
		}
	}
	skydb := &SkyDB{
		r: registry.New(&client.Client{Options: opts}, pk, sk),
	}
	return skydb, nil
}

// Read retrieves from SkyDB the data that corresponds to the given key set.
func (db SkyDB) Read(dataKey crypto.Hash) ([]byte, uint64, error) {
	s, rev, err := db.r.Read(dataKey)
	if err != nil && (strings.Contains(err.Error(), renter.ErrRegistryEntryNotFound.Error()) || strings.Contains(err.Error(), renter.ErrRegistryLookupTimeout.Error())) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, errors.AddContext(err, "skydb failed to read from registry")
	}
	b, err := db.r.Client.SkynetSkylinkGet(s.String())
	if err != nil && strings.Contains(err.Error(), renter.ErrRootNotFound.Error()) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, errors.AddContext(err, "failed to download data from Skynet")
	}
	return b, rev, nil
}

// Write stores the given `data` in SkyDB under the given key set.
func (db SkyDB) Write(data []byte, dataKey crypto.Hash, rev uint64) error {
	skylink, err := uploadData(db.r.Client, data)
	if err != nil {
		return errors.AddContext(err, "failed to upload data")
	}
	_, err = db.r.Write(skylink, dataKey, rev)
	if err != nil {
		return errors.AddContext(err, "failed to write to the registry")
	}
	return nil
}

// uploadData uploads the given data to skynet and returns a SkylinkV1.
func uploadData(c *client.Client, content []byte) (string, error) {
	sup := &skymodules.SkyfileUploadParameters{
		SiaPath:  skymodules.RandomSkynetFilePath(),
		Filename: "data.json",
		Force:    true,
		Mode:     skymodules.DefaultFilePerm,
		Reader:   bytes.NewReader(content),
	}
	skylink, _, err := c.SkynetSkyfilePost(*sup)
	if err != nil {
		return "", errors.AddContext(err, "failed to upload")
	}
	return skylink, nil
}
