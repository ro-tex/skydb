package registry

import (
	"gitlab.com/NebulousLabs/errors"
	"gitlab.com/SkynetLabs/skyd/node/api/client"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
)

// Registry is a decentralized key-value store that allows storing small amounts
// of data on Sia hosts.
//
// See https://blog.sia.tech/the-host-registry-building-dynamic-content-on-skynet-ade72ba6f30b
type Registry struct {
	Client *client.Client
	sk     crypto.SecretKey
	pk     crypto.PublicKey
	spk    types.SiaPublicKey
}

// New initialises and returns a new Registry instance.
func New(c *client.Client, pk crypto.PublicKey, sk crypto.SecretKey) *Registry {
	return &Registry{
		Client: c,
		sk:     sk,
		pk:     pk,
		spk:    types.Ed25519PublicKey(pk),
	}
}

// Read reads a registry entry and returns the SkylinkV2 it contains,
// as well as the revision.
func (r Registry) Read(dataKey crypto.Hash) (skymodules.Skylink, uint64, error) {
	srv, err := r.Client.RegistryRead(r.spk, dataKey)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "failed to read from the registry")
	}
	err = srv.Verify(r.pk)
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

// Write updates the registry entry with the given dataKey to contain
// the given skylink. Returns a SkylinkV2.
func (r Registry) Write(skylink string, dataKey crypto.Hash, rev uint64) (skymodules.Skylink, error) {
	var sl skymodules.Skylink
	err := sl.LoadString(skylink)
	if err != nil {
		return skymodules.Skylink{}, errors.AddContext(err, "failed to load skylink data")
	}
	// Update the registry with that link.
	srv := modules.NewRegistryValue(dataKey, sl.Bytes(), rev, modules.RegistryTypeWithoutPubkey).Sign(r.sk)
	err = r.Client.RegistryUpdate(r.spk, dataKey, srv.Revision, srv.Signature, sl)
	if err != nil {
		return skymodules.Skylink{}, err
	}
	return skymodules.NewSkylinkV2(r.spk, dataKey), nil
}
