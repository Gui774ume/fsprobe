/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package model

import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/utils"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DentryResolver - Path resolver for the path fragments and single fragment methods
type DentryResolver interface {
	ResolveInode(mountID uint32, inode uint64) (string, error)
	RemoveInode(mountID uint32, inode uint64) error
	ResolveKey(key uint32, length uint32) (string, error)
	RemoveEntry(key uint32) error
	AddCacheEntry(key uint32, value interface{}) error
}

// PathFragmentsKey - Key of a dentry cache hashmap
type PathFragmentsKey struct {
	inode   uint64
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
	parent   PathFragmentsKey
	Fragment [PathFragmentsSize]byte
}

// Read - Reads the provided data into the buffer
func (pfv *PathFragmentsValue) Read(data []byte) error {
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
	key   *PathFragmentsKey
	value *PathFragmentsValue
}

// NewPathFragmentsResolver - Returns a new PathFragmentsResolver instance
func NewPathFragmentsResolver(monitor *Monitor) (*PathFragmentsResolver, error) {
	cache := monitor.GetMap(PathFragmentsMap)
	if cache == nil {
		return nil, fmt.Errorf("%s eBPF map doesn't exist", PathFragmentsMap)
	}
	return &PathFragmentsResolver{
		cache: cache,
		key:   &PathFragmentsKey{},
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

// RemoveInode - Removes a pathname from the kernel cache using the provided mount id and inode
func (pfr *PathFragmentsResolver) RemoveInode(mountID uint32, inode uint64) error {
	// Don't resolve path if pathnameKey isn't valid
	pfr.key.Set(mountID, inode)
	if pfr.key.IsNull() {
		return fmt.Errorf("invalid inode/dev couple: %s", pfr.key.String())
	}
	keyB := pfr.key.GetKeyBytes()
	// Delete entry
	return pfr.cache.Delete(keyB)
}

// ResolveKey - Does nothing
func (pfr *PathFragmentsResolver) ResolveKey(key uint32, length uint32) (string, error) {
	return "", nil
}

// AddCacheEntry - Adds a new entry in the user space cache
func (pfr *PathFragmentsResolver) AddCacheEntry(key uint32, value interface{}) error {
	return nil
}

// RemoveEntry - Removes an entry from the cache
func (pfr *PathFragmentsResolver) RemoveEntry(key uint32) error {
	return nil
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
	Fragment [SingleFragmentSize]byte
}

// Read - Reads the provided data into the buffer
func (sfv *SingleFragmentValue) Read(data []byte) error {
	return binary.Read(bytes.NewBuffer(data), utils.ByteOrder, &sfv.Fragment)
}

// GetString - Returns the path as a string
func (sfv *SingleFragmentValue) GetString(length uint32) string {
	if length > 0 {
		return decodePath(sfv.Fragment[:length])
	}
	return decodePath(sfv.Fragment[:])
}

type SingleFragmentResolver struct {
	cache *ebpf.Map
	key   *SingleFragmentKey
	value *SingleFragmentValue
}

// NewSingleFragmentResolver - Returns a new SingleFragmentResolver instance
func NewSingleFragmentResolver(monitor *Monitor) (*SingleFragmentResolver, error) {
	cache := monitor.GetMap(SingleFragmentsMap)
	if cache == nil {
		return nil, fmt.Errorf("%s eBPF map doesn't exist", SingleFragmentsMap)
	}
	return &SingleFragmentResolver{
		cache: cache,
		key:   &SingleFragmentKey{},
		value: &SingleFragmentValue{},
	}, nil
}

// ResolveInode - Does nothing
func (sfr *SingleFragmentResolver) ResolveInode(mountID uint32, inode uint64) (filename string, err error) {
	return "", nil
}

// RemoveInode - Removes a pathname from the kernel cache using the provided mount id and inode
func (sfr *SingleFragmentResolver) RemoveInode(mountID uint32, inode uint64) error {
	return nil
}

// Resolve - Resolves a pathname from the provided mount id and inode
func (sfr *SingleFragmentResolver) ResolveKey(key uint32, length uint32) (filename string, err error) {
	// Don't resolve path if pathnameKey isn't valid
	sfr.key.Set(key)
	if sfr.key.IsNull() {
		return "", fmt.Errorf("invalid key: %s", sfr.key.String())
	}
	// Generate hashmap key
	keyB := sfr.key.GetKeyBytes()
	valueB := []byte{}
	// Fetch hashmap value
	if valueB, err = sfr.cache.GetBytes(keyB); err != nil || len(valueB) == 0 {
		filename = "*ERROR*"
		err = errors.Wrap(err, "failed to query value")
		return
	}
	// Read fragment from valueB
	if err = sfr.value.Read(valueB); err != nil {
		filename = "*ERROR*"
		err = errors.Wrap(err, "failed to decode fragment")
		return
	}
	filename = sfr.value.GetString(length)
	if len(filename) == 0 {
		filename = "/"
	}
	return
}

// AddCacheEntry - Adds a new entry in the user space cache
func (sfr *SingleFragmentResolver) AddCacheEntry(key uint32, value interface{}) error {
	return nil
}

// RemoveEntry - Removes an entry from the cache
func (sfr *SingleFragmentResolver) RemoveEntry(key uint32) error {
	// Don't resolve path if pathnameKey isn't valid
	sfr.key.Set(key)
	if sfr.key.IsNull() {
		return fmt.Errorf("invalid key: %s", sfr.key.String())
	}
	// Generate hashmap key
	keyB := sfr.key.GetKeyBytes()
	// Delete entry
	if err := sfr.cache.Delete(keyB); err != nil {
		return errors.Wrapf(err, "failed to delete entry at %s", sfr.key.String())
	}
	return nil
}

type PerfBufferResolver struct {
	kernelLRU *ebpf.Map
	lru       *lru.Cache
}

// NewPerfBufferResolver - Returns a new PerfBufferResolver instance
func NewPerfBufferResolver(monitor *Monitor) (*PerfBufferResolver, error) {
	var err error
	pbr := PerfBufferResolver{}
	pbr.kernelLRU = monitor.GetMap(CachedInodesMap)
	if pbr.kernelLRU == nil {
		return nil, fmt.Errorf("%s eBPF map doesn't exist", CachedInodesMap)
	}
	pbr.lru, err = lru.NewWithEvict(PerfBufferCachedInodesSize, pbr.onCachedInodeEvicted)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create a new PerfBufferResolver LRU")
	}
	return &pbr, nil
}

// ResolveInode - Does nothing
func (pbr *PerfBufferResolver) ResolveInode(mountID uint32, inode uint64) (filename string, err error) {
	return "", nil
}

// RemoveInode - Removes a pathname from the kernel cache using the provided mount id and inode
func (pbr *PerfBufferResolver) RemoveInode(mountID uint32, inode uint64) error {
	return nil
}

// Resolve - Resolves a pathname from the provided key (length is not used)
func (pbr *PerfBufferResolver) ResolveKey(key uint32, length uint32) (string, error) {
	// Select the inode path from the lru
	value, ok := pbr.lru.Get(key)
	if ok {
		return value.(string), nil
	}
	if key == 2 {
		return "/", nil
	}
	return "", fmt.Errorf("%v not found", key)
}

// AddCacheEntry - Adds a new entry in the LRU cache
func (pbr *PerfBufferResolver) AddCacheEntry(key uint32, value interface{}) error {
	// Add entry in user space LRU
	pbr.lru.Add(key, value)
	// Add entry in the kernel space cache
	keyB := make([]byte, 4)
	utils.ByteOrder.PutUint32(keyB, key)
	var valueB byte
	if err := pbr.kernelLRU.Put(keyB, valueB); err != nil {
		return err
	}
	return nil
}

// RemoveEntry - Removes an entry from the cache
func (pbr *PerfBufferResolver) RemoveEntry(key uint32) error {
	keyB := make([]byte, 4)
	utils.ByteOrder.PutUint32(keyB, key)
	if err := pbr.kernelLRU.Delete(keyB); err != nil {
		return errors.Wrap(err, "failed to delete entry from cached_inodes eBPF map")
	}
	return nil
}

// onCachedInodeEvicted - Removes the input inode from the kernel space cache
func (pbr *PerfBufferResolver) onCachedInodeEvicted(key, value interface{}) {
	keyB := make([]byte, 4)
	keyU, ok := key.(uint32)
	if !ok {
		logrus.Warnf("failed to delete entry from cached_inodes eBPF map: key is not uint32: %v", key)
	}
	utils.ByteOrder.PutUint32(keyB, keyU)
	if err := pbr.kernelLRU.Delete(keyB); err != nil {
		logrus.Warnf("failed to delete entry from cached_inodes eBPF map: %v", err)
	}
}

// NewDentryResolver - Returns a new resolver configured for the selected resolution method
func NewDentryResolver(monitor *Monitor) (DentryResolver, error) {
	switch monitor.Options.DentryResolutionMode {
	case DentryResolutionFragments:
		return NewPathFragmentsResolver(monitor)
	case DentryResolutionSingleFragment:
		return NewSingleFragmentResolver(monitor)
	case DentryResolutionPerfBuffer:
		return NewPerfBufferResolver(monitor)
	}
	return nil, errors.New("unknown dentry resolution mode")
}
