package skydb

import (
	"bytes"
	"reflect"
	"strings"

	"gitlab.com/NebulousLabs/errors"
	"gitlab.com/SkynetLabs/skyd/node/api/client"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"gitlab.com/SkynetLabs/skyd/skymodules/renter"
	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
)

var (
	// ErrNotFound is returned when an entry is not found.
	ErrNotFound = errors.New("skydb entry not found")
)

// SkyDBI is the interface for communicating with SkyDB. We use an interface, so
// we can easily override it for testing purposes.
type SkyDBI interface {
	Read(hash crypto.Hash) ([]byte, uint64, error)
	Write(data []byte, dataKey crypto.Hash, rev uint64) error
}

type SkyDB struct {
	Client *client.Client
	sk     crypto.SecretKey
	pk     crypto.PublicKey
}

// New creates a new SkyDB client with the given options.
// If the options are empty we'll look for skyd at localhost:9980 and we'll use
// "Sia-Agent" as user agent and we'll try to get the password for skyd from the
// environment.
func New(sk crypto.SecretKey, pk crypto.PublicKey, opts client.Options) (*SkyDB, error) {
	if reflect.DeepEqual(opts, client.Options{}) {
		var err error
		opts, err = client.DefaultOptions()
		if err != nil {
			return nil, errors.AddContext(err, "failed to get default client options")
		}
	}
	skydb := &SkyDB{
		Client: &client.Client{Options: opts},
		sk:     sk,
		pk:     pk,
	}
	return skydb, nil
}

// Read retrieves from SkyDB the data that corresponds to the given key set.
func (db SkyDB) Read(dataKey crypto.Hash) ([]byte, uint64, error) {
	s, rev, err := db.registryRead(dataKey)
	if err != nil && (strings.Contains(err.Error(), renter.ErrRegistryEntryNotFound.Error()) || strings.Contains(err.Error(), renter.ErrRegistryLookupTimeout.Error())) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, errors.AddContext(err, "skydb failed to read from registry")
	}
	b, err := db.Client.SkynetSkylinkGet(s.String())
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
	skylink, err := uploadData(db.Client, data)
	if err != nil {
		return errors.AddContext(err, "failed to upload data")
	}
	_, err = db.registryWrite(skylink, dataKey, rev)
	if err != nil {
		return errors.AddContext(err, "failed to write to the registry")
	}
	return nil
}

// registryWrite updates the registry entry with the given dataKey to contain
// the given skylink. Returns a SkylinkV2.
func (db SkyDB) registryWrite(skylink string, dataKey crypto.Hash, rev uint64) (skymodules.Skylink, error) {
	var sl skymodules.Skylink
	err := sl.LoadString(skylink)
	if err != nil {
		return skymodules.Skylink{}, errors.AddContext(err, "failed to load skylink data")
	}
	// Update the registry with that link.
	spk := types.Ed25519PublicKey(db.pk)
	srv := modules.NewRegistryValue(dataKey, sl.Bytes(), rev, modules.RegistryTypeWithoutPubkey).Sign(db.sk)
	err = db.Client.RegistryUpdate(spk, dataKey, srv.Revision, srv.Signature, sl)
	if err != nil {
		return skymodules.Skylink{}, err
	}
	return skymodules.NewSkylinkV2(spk, dataKey), nil
}

// registryRead reads a registry entry and returns the SkylinkV2 it contains,
// as well as the revision.
func (db SkyDB) registryRead(dataKey crypto.Hash) (skymodules.Skylink, uint64, error) {
	spk := types.Ed25519PublicKey(db.pk)
	srv, err := db.Client.RegistryRead(spk, dataKey)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "failed to read from the registry")
	}
	err = srv.Verify(db.pk)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "the value we read failed validation")
	}
	var sl skymodules.Skylink
	err = sl.LoadBytes(srv.Data)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "registry value is not a valid skylink")
	}
	return sl, srv.Revision, nil
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
