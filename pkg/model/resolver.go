package model

import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"unsafe"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/utils"
)

const (
	// FragmentsSection - This map holds the cache of resolved dentries for the path fragments method
	PathFragmentsSection = "path_fragments"
	// PathFragmentsSize - Size of the fragments used by the path fragments method
	PathFragmentsSize = 256
	// SingleFragmentSection - This map holds the cache of resolved dentries for the single fragment method
	SingleFragmentsSection = "single_fragments"
	// SingleFragmentSize - Size of the single fragment used by the single fragment method
	SingleFragmentSize = 4351
)

// DentryResolver - Path resolver for the path fragments and single fragment methods
type DentryResolver interface {
	ResolveInode(mountID uint32, inode uint64) (string, error)
	ResolveKey(key uint32, length uint32) (string, error)
}

// PathFragmentsKey - Key of a dentry cache hashmap
type PathFragmentsKey struct {
	inode uint64
	mountID uint32
}

func (pfk *PathFragmentsKey) Set(mountID uint32, inode uint64) {
	pfk.mountID = mountID
	pfk.inode = inode
}

func (pfk *PathFragmentsKey) Write(buffer []byte) {
	utils.ByteOrder.PutUint64(buffer[0:8], pfk.inode)
	utils.ByteOrder.PutUint32(buffer[8:12], pfk.mountID)
	utils.ByteOrder.PutUint32(buffer[12:16], 0)
}

func (pfk *PathFragmentsKey) GetKeyBytes() []byte {
	keyB := make([]byte, 16)
	pfk.Write(keyB)
	return keyB[:]
}

func (pfk *PathFragmentsKey) Read(buffer []byte) int {
	pfk.inode = utils.ByteOrder.Uint64(buffer[0:8])
	pfk.mountID = utils.ByteOrder.Uint32(buffer[8:12])
	return 16
}

func (pfk *PathFragmentsKey) IsNull() bool {
	return pfk.inode == 0 && pfk.mountID == 0
}

func (pfk *PathFragmentsKey) HasEmptyInode() bool {
	return pfk.inode == 0
}

func (pfk *PathFragmentsKey) String() string {
	return fmt.Sprintf("%x/%x", pfk.mountID, pfk.inode)
}

type PathFragmentsValue struct {
	parent PathFragmentsKey
	Fragment   [PathFragmentsSize]byte
}

// Read - Reads the provided data into the buffer
func (pfv *PathFragmentsValue) Read(data []byte) (error) {
	return binary.Read(bytes.NewBuffer(data), utils.ByteOrder, &pfv.Fragment)
}

// IsRoot - Returns true if the current fragment is the root of a mount point
func (pfv *PathFragmentsValue) IsRoot() bool {
	if pfv.Fragment[0] == 47 {
		return true
	}
	return false
}

// GetString - Returns the path as a string
func (pfv *PathFragmentsValue) GetString() string {
	return C.GoString((*C.char)(unsafe.Pointer(&pfv.Fragment)))
}

// PathFragmentsResolver - Dentry resolver of the path fragments method
type PathFragmentsResolver struct {
	cache *ebpf.Map
	key *PathFragmentsKey
	value *PathFragmentsValue
}

// NewPathFragmentsResolver - Returns a new PathFragmentsResolver instance
func NewPathFragmentsResolver(monitor *Monitor) (*PathFragmentsResolver, error) {
	cache := monitor.GetMap(PathFragmentsSection)
	if cache == nil {
		return nil, fmt.Errorf("%s BPF_HASH table doesn't exist", PathFragmentsSection)
	}
	return &PathFragmentsResolver{
		cache: cache,
		key: &PathFragmentsKey{},
		value: &PathFragmentsValue{},
	}, nil
}

// ResolveInode - Resolves a pathname from the provided mount id and inode
func (pfr *PathFragmentsResolver) ResolveInode(mountID uint32, inode uint64) (filename string, err error) {
	// Don't resolve path if pathnameKey isn't valid
	pfr.key.Set(mountID, inode)
	if pfr.key.IsNull() {
		return "", fmt.Errorf("invalid inode/dev couple: %s", pfr.key.String())
	}

	keyB := pfr.key.GetKeyBytes()
	valueB := []byte{}
	done := false
	// Fetch path recursively
	for !done {
		if valueB, err = pfr.cache.GetBytes(keyB); err != nil || len(valueB) == 0 {
			filename = "*ERROR*" + filename
			break
		}
		// Read next key from valueB
		read := pfr.key.Read(valueB)
		// Read current fragment from valueB
		if err = pfr.value.Read(valueB[read:]); err != nil {
			err = errors.Wrap(err, "failed to decode fragment")
			break
		}

		// Don't append dentry name if this is the root dentry (i.d. name == '/')
		if !pfr.value.IsRoot() {
			filename = "/" + pfr.value.GetString() + filename
		}

		if pfr.key.HasEmptyInode() {
			break
		}

		// Prepare next key
		pfr.key.Write(keyB)
	}

	if len(filename) == 0 {
		filename = "/"
	}

	return
}

// ResolveKey - Does nothing
func (pfr *PathFragmentsResolver) ResolveKey(key uint32, length uint32) (string, error) {
	return "", nil
}

// SingleFragmentKey - Key of a dentry cache hashmap
type SingleFragmentKey struct {
	key uint32
}

func (sfk *SingleFragmentKey) Set(key uint32) {
	sfk.key = key
}

func (sfk *SingleFragmentKey) Write(buffer []byte) {
	utils.ByteOrder.PutUint32(buffer[0:4], sfk.key)
}

func (sfk *SingleFragmentKey) GetKeyBytes() []byte {
	keyB := make([]byte, 4)
	sfk.Write(keyB)
	return keyB
}

func (sfk *SingleFragmentKey) IsNull() bool {
	return sfk.key == 0
}

func (sfk *SingleFragmentKey) String() string {
	return fmt.Sprintf("%x", sfk.key)
}

type SingleFragmentValue struct {
	Fragment   [SingleFragmentSize]byte
}

// Read - Reads the provided data into the buffer
func (sfv *SingleFragmentValue) Read(data []byte) (error) {
	return binary.Read(bytes.NewBuffer(data), utils.ByteOrder, &sfv.Fragment)
}

// GetString - Returns the path as a string
func (sfv *SingleFragmentValue) GetString(length uint32) string {
	return decodePath(sfv.Fragment[:length])
}

type SingleFragmentResolver struct {
	cache *ebpf.Map
	key *SingleFragmentKey
	value *SingleFragmentValue
}

// NewSingleFragmentResolver - Returns a new SingleFragmentResolver instance
func NewSingleFragmentResolver(monitor *Monitor) (*SingleFragmentResolver, error) {
	cache := monitor.GetMap(SingleFragmentsSection)
	if cache == nil {
		return nil, fmt.Errorf("%s BPF_HASH table doesn't exist", SingleFragmentsSection)
	}
	return &SingleFragmentResolver{
		cache: cache,
		key: &SingleFragmentKey{},
		value: &SingleFragmentValue{},
	}, nil
}

// ResolveInode - Does nothing
func (sfr *SingleFragmentResolver) ResolveInode(mountID uint32, inode uint64) (filename string, err error) {
	return "", nil
}

// Resolve - Resolves a pathname from the provided mount id and inode
func (pfr *SingleFragmentResolver) ResolveKey(key uint32, length uint32) (filename string, err error) {
	// Don't resolve path if pathnameKey isn't valid
	pfr.key.Set(key)
	if pfr.key.IsNull() {
		return "", fmt.Errorf("invalid inode/dev couple: %s", pfr.key.String())
	}
	// Generate hashmap key
	keyB := pfr.key.GetKeyBytes()
	valueB := []byte{}
	// Fetch hashmap value
	if valueB, err = pfr.cache.GetBytes(keyB); err != nil || len(valueB) == 0 {
		filename = "*ERROR*"
		err = errors.Wrap(err, "failed to query value")
		return
	}
	// Read fragment from valueB
	if err = pfr.value.Read(valueB); err != nil {
		filename = "*ERROR*"
		err = errors.Wrap(err, "failed to decode fragment")
		return
	}
	filename = pfr.value.GetString(length)
	if len(filename) == 0 {
		filename = "/"
	}
	return
}

// NewDentryResolver - Returns a new resolver configured for the selected resolution method
func NewDentryResolver(monitor *Monitor) (DentryResolver, error) {
	switch monitor.Options.DentryResolutionMode {
	case DentryResolutionFragments:
		return NewPathFragmentsResolver(monitor)
	case DentryResolutionSingleFragment:
		return NewSingleFragmentResolver(monitor)
	}
	return nil, errors.New("unknown dentry resolution mode")
}
