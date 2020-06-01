package utils

import (
	"C"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// GetPpid is a fallback to read the parent PID from /proc.
// Some kernel versions, like 4.13.0 return 0 getting the parent PID
// from the current task, so we need to use this fallback to have
// the parent PID in any kernel.
func GetPpid(pid uint32) uint32 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return uint32(i)
		}
	}
	return 0
}

// getNamespaceID - Returns the namespace id in brackets
func getNamespaceID(raw string) uint64 {
	i := strings.Index(raw, "[")
	if i > 0 {
		id, err := strconv.ParseUint(raw[i+1:len(raw)-1], 10, 64)
		if err != nil {
			return 0
		}
		return id
	}
	return 0
}

// GetPidnsFromPid - Returns the pid namespace of a process
func GetPidnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/pid_for_children", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetNetnsFromPid - Returns the network namespace of a process
func GetNetnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/net", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetUsernsFromPid - Returns the user namespace of a process
func GetUsernsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/user", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetMntnsFromPid - Returns the mount namespace of a process
func GetMntnsFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/mnt", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetCgroupFromPid - Returns the cgroup of a process
func GetCgroupFromPid(pid uint32) uint64 {
	raw, err := os.Readlink(fmt.Sprintf("/proc/%v/ns/cgroup", pid))
	if err != nil {
		return 0
	}
	return getNamespaceID(raw)
}

// GetCommFromPid - Returns the comm of a process
func GetCommFromPid(pid uint32) string {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/comm", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.Replace(string(raw), "\n", "", -1)
}

// InterfaceToBytes - Tranforms an interface into a C bytes array
func InterfaceToBytes(data interface{}, byteOrder binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, byteOrder, data); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// GetHostByteOrder - Returns the host byte order
func GetHostByteOrder() binary.ByteOrder {
	if isBigEndian() {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}

func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// ByteOrder - host byte order
var ByteOrder binary.ByteOrder

func init() {
	ByteOrder = getHostByteOrder()
}

// String - No copy bytes to string conversion
func String(bytes []byte) string {
	hdr := *(*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	return *(*string)(unsafe.Pointer(&reflect.StringHeader{
		Data: hdr.Data,
		Len:  hdr.Len,
	}))
}

// Bytes - No copy string to bytes conversion
func Bytes(str string) []byte {
	hdr := *(*reflect.StringHeader)(unsafe.Pointer(&str))
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: hdr.Data,
		Len:  hdr.Len,
		Cap:  hdr.Len,
	}))
}
