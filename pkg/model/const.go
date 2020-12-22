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

import "fmt"

var (
	// DentryResolutionModeConst - In-kernel configuration constant
	DentryResolutionModeConst = "dentry_resolution_mode"
	// InodeFilteringModeConst - In-kernel configuration constant
	InodeFilteringModeConst = "inode_filtering_mode"
	// FollowModeConst - In-kernel configuration constant
	FollowModeConst = "follow_mode"
	// RecursiveModeConst - In-kernel configuration constant
	RecursiveModeConst = "recursive_mode"
)

// DentryResolutionMode - Mode of resolution of the kernel dentries
type DentryResolutionMode uint64

const (
	DentryResolutionFragments      DentryResolutionMode = 0
	DentryResolutionSingleFragment DentryResolutionMode = 1
	DentryResolutionPerfBuffer     DentryResolutionMode = 2
)

// ErrValue - Return value
type ErrValue int32

const (
	EPERM                 ErrValue = 1      /* Operation not permitted */
	ENOENT                ErrValue = 2      /* No such file or directory */
	ESRCH                 ErrValue = 3      /* No such process */
	EINTR                 ErrValue = 4      /* Interrupted system call */
	EIO                   ErrValue = 5      /* I/O error */
	ENXIO                 ErrValue = 6      /* No such device or address */
	E2BIG                 ErrValue = 7      /* Argument list too long */
	ENOEXEC               ErrValue = 8      /* Exec format error */
	EBADF                 ErrValue = 9      /* Bad file number */
	ECHILD                ErrValue = 10     /* No child processes */
	EAGAIN                ErrValue = 11     /* Try again */
	ENOMEM                ErrValue = 12     /* Out of memory */
	EACCES                ErrValue = 13     /* Permission denied */
	EFAULT                ErrValue = 14     /* Bad address */
	ENOTBLK               ErrValue = 15     /* Block device required */
	EBUSY                 ErrValue = 16     /* Device or resource busy */
	EEXIST                ErrValue = 17     /* File exists */
	EXDEV                 ErrValue = 18     /* Cross-device link */
	ENODEV                ErrValue = 19     /* No such device */
	ENOTDIR               ErrValue = 20     /* Not a directory */
	EISDIR                ErrValue = 21     /* Is a directory */
	EINVAL                ErrValue = 22     /* Invalid argument */
	ENFILE                ErrValue = 23     /* File table overflow */
	EMFILE                ErrValue = 24     /* Too many open files */
	ENOTTY                ErrValue = 25     /* Not a typewriter */
	ETXTBSY               ErrValue = 26     /* Text file busy */
	EFBIG                 ErrValue = 27     /* File too large */
	ENOSPC                ErrValue = 28     /* No space left on device */
	ESPIPE                ErrValue = 29     /* Illegal seek */
	EROFS                 ErrValue = 30     /* Read-only file system */
	EMLINK                ErrValue = 31     /* Too many links */
	EPIPE                 ErrValue = 32     /* Broken pipe */
	EDOM                  ErrValue = 33     /* Math argument out of domain of func */
	ERANGE                ErrValue = 34     /* Math result not representable */
	EDEADLK               ErrValue = 35     /* Resource deadlock would occur */
	ENAMETOOLONG          ErrValue = 36     /* File name too long */
	ENOLCK                ErrValue = 37     /* No record locks available */
	ENOSYS                ErrValue = 38     /* Invalid system call number */
	ENOTEMPTY             ErrValue = 39     /* Directory not empty */
	ELOOP                 ErrValue = 40     /* Too many symbolic links encountered */
	EWOULDBLOCK           ErrValue = EAGAIN /* Operation would block */
	ENOMSG                ErrValue = 42     /* No message of desired type */
	EIDRM                 ErrValue = 43     /* Identifier removed */
	ECHRNG                ErrValue = 44     /* Channel number out of range */
	EL2NSYNC              ErrValue = 45     /* Level 2 not synchronized */
	EL3HLT                ErrValue = 46     /* Level 3 halted */
	EL3RST                ErrValue = 47     /* Level 3 reset */
	ELNRNG                ErrValue = 48     /* Link number out of range */
	EUNATCH               ErrValue = 49     /* Protocol driver not attached */
	ENOCSI                ErrValue = 50     /* No CSI structure available */
	EL2HLT                ErrValue = 51     /* Level 2 halted */
	EBADE                 ErrValue = 52     /* Invalid exchange */
	EBADR                 ErrValue = 53     /* Invalid request descriptor */
	EXFULL                ErrValue = 54     /* Exchange full */
	ENOANO                ErrValue = 55     /* No anode */
	EBADRQC               ErrValue = 56     /* Invalid request code */
	EBADSLT               ErrValue = 57     /* Invalid slot */
	EDEADLOCK             ErrValue = EDEADLK
	EBFONT                ErrValue = 59  /* Bad font file format */
	ENOSTR                ErrValue = 60  /* Device not a stream */
	ENODATA               ErrValue = 61  /* No data available */
	ETIME                 ErrValue = 62  /* Timer expired */
	ENOSR                 ErrValue = 63  /* Out of streams resources */
	ENONET                ErrValue = 64  /* Machine is not on the network */
	ENOPKG                ErrValue = 65  /* Package not installed */
	EREMOTE               ErrValue = 66  /* Object is remote */
	ENOLINK               ErrValue = 67  /* Link has been severed */
	EADV                  ErrValue = 68  /* Advertise error */
	ESRMNT                ErrValue = 69  /* Srmount error */
	ECOMM                 ErrValue = 70  /* Communication error on send */
	EPROTO                ErrValue = 71  /* Protocol error */
	EMULTIHOP             ErrValue = 72  /* Multihop attempted */
	EDOTDOT               ErrValue = 73  /* RFS specific error */
	EBADMSG               ErrValue = 74  /* Not a data message */
	EOVERFLOW             ErrValue = 75  /* Value too large for defined data type */
	ENOTUNIQ              ErrValue = 76  /* Name not unique on network */
	EBADFD                ErrValue = 77  /* File descriptor in bad state */
	EREMCHG               ErrValue = 78  /* Remote address changed */
	ELIBACC               ErrValue = 79  /* Can not access a needed shared library */
	ELIBBAD               ErrValue = 80  /* Accessing a corrupted shared library */
	ELIBSCN               ErrValue = 81  /* .lib section in a.out corrupted */
	ELIBMAX               ErrValue = 82  /* Attempting to link in too many shared libraries */
	ELIBEXEC              ErrValue = 83  /* Cannot exec a shared library directly */
	EILSEQ                ErrValue = 84  /* Illegal byte sequence */
	ERESTART              ErrValue = 85  /* Interrupted system call should be restarted */
	ESTRPIPE              ErrValue = 86  /* Streams pipe error */
	EUSERS                ErrValue = 87  /* Too many users */
	ENOTSOCK              ErrValue = 88  /* Socket operation on non-socket */
	EDESTADDRREQ          ErrValue = 89  /* Destination address required */
	EMSGSIZE              ErrValue = 90  /* Message too long */
	EPROTOTYPE            ErrValue = 91  /* Protocol wrong type for socket */
	ENOPROTOOPT           ErrValue = 92  /* Protocol not available */
	EPROTONOSUPPORT       ErrValue = 93  /* Protocol not supported */
	ESOCKTNOSUPPORT       ErrValue = 94  /* Socket type not supported */
	EOPNOTSUPP            ErrValue = 95  /* Operation not supported on transport endpoint */
	EPFNOSUPPORT          ErrValue = 96  /* Protocol family not supported */
	EAFNOSUPPORT          ErrValue = 97  /* Address family not supported by protocol */
	EADDRINUSE            ErrValue = 98  /* Address already in use */
	EADDRNOTAVAIL         ErrValue = 99  /* Cannot assign requested address */
	ENETDOWN              ErrValue = 100 /* Network is down */
	ENETUNREACH           ErrValue = 101 /* Network is unreachable */
	ENETRESET             ErrValue = 102 /* Network dropped connection because of reset */
	ECONNABORTED          ErrValue = 103 /* Software caused connection abort */
	ECONNRESET            ErrValue = 104 /* Connection reset by peer */
	ENOBUFS               ErrValue = 105 /* No buffer space available */
	EISCONN               ErrValue = 106 /* Transport endpoint is already connected */
	ENOTCONN              ErrValue = 107 /* Transport endpoint is not connected */
	ESHUTDOWN             ErrValue = 108 /* Cannot send after transport endpoint shutdown */
	ETOOMANYREFS          ErrValue = 109 /* Too many references: cannot splice */
	ETIMEDOUT             ErrValue = 110 /* Connection timed out */
	ECONNREFUSED          ErrValue = 111 /* Connection refused */
	EHOSTDOWN             ErrValue = 112 /* Host is down */
	EHOSTUNREACH          ErrValue = 113 /* No route to host */
	EALREADY              ErrValue = 114 /* Operation already in progress */
	EINPROGRESS           ErrValue = 115 /* Operation now in progress */
	ESTALE                ErrValue = 116 /* Stale file handle */
	EUCLEAN               ErrValue = 117 /* Structure needs cleaning */
	ENOTNAM               ErrValue = 118 /* Not a XENIX named type file */
	ENAVAIL               ErrValue = 119 /* No XENIX semaphores available */
	EISNAM                ErrValue = 120 /* Is a named type file */
	EREMOTEIO             ErrValue = 121 /* Remote I/O error */
	EDQUOT                ErrValue = 122 /* Quota exceeded */
	ENOMEDIUM             ErrValue = 123 /* No medium found */
	EMEDIUMTYPE           ErrValue = 124 /* Wrong medium type */
	ECANCELED             ErrValue = 125 /* Operation Canceled */
	ENOKEY                ErrValue = 126 /* Required key not available */
	EKEYEXPIRED           ErrValue = 127 /* Key has expired */
	EKEYREVOKED           ErrValue = 128 /* Key has been revoked */
	EKEYREJECTED          ErrValue = 129 /* Key was rejected by service */
	EOWNERDEAD            ErrValue = 130 /* Owner died */
	ENOTRECOVERABLE       ErrValue = 131 /* State not recoverable */
	ERFKILL               ErrValue = 132 /* Operation not possible due to RF-kill */
	EHWPOISON             ErrValue = 133 /* Memory page has hardware error */
	ERESTARTSYS           ErrValue = 512
	ERESTARTNOINTR        ErrValue = 513
	ERESTARTNOHAND        ErrValue = 514 /* restart if no handler.. */
	ENOIOCTLCMD           ErrValue = 515 /* No ioctl command */
	ERESTART_RESTARTBLOCK ErrValue = 516 /* restart by calling sys_restart_syscall */
	EPROBE_DEFER          ErrValue = 517 /* Driver requests probe retry */
	EOPENSTALE            ErrValue = 518 /* open found a stale dentry */
	ENOPARAM              ErrValue = 519 /* Parameter not supported */

	/* Defined for the NFSv3 protocol */
	EBADHANDLE      ErrValue = 521 /* Illegal NFS file handle */
	ENOTSYNC        ErrValue = 522 /* Update synchronization mismatch */
	EBADCOOKIE      ErrValue = 523 /* Cookie is stale */
	ENOTSUPP        ErrValue = 524 /* Operation is not supported */
	ETOOSMALL       ErrValue = 525 /* Buffer or request is too small */
	ESERVERFAULT    ErrValue = 526 /* An untranslatable error occurred */
	EBADTYPE        ErrValue = 527 /* Type not supported by server */
	EJUKEBOX        ErrValue = 528 /* Request initiated, but will not complete before timeout */
	EIOCBQUEUED     ErrValue = 529 /* iocb queued, will get completion event */
	ERECALLCONFLICT ErrValue = 530 /* conflict with recalled state */
)

// ErrValueToString - Returns an err as its string representation
func ErrValueToString(input int32) string {
	if input >= 0 {
		return fmt.Sprintf("%v", input)
	}
	switch ErrValue(-input) {
	case EPERM:
		return "EPERM"
	case ENOENT:
		return "ENOENT"
	case ESRCH:
		return "ESRCH"
	case EINTR:
		return "EINTR"
	case EIO:
		return "EIO"
	case ENXIO:
		return "ENXIO"
	case E2BIG:
		return "E2BIG"
	case ENOEXEC:
		return "ENOEXEC"
	case EBADF:
		return "EBADF"
	case ECHILD:
		return "ECHILD"
	case EAGAIN:
		return "EAGAIN"
	case ENOMEM:
		return "ENOMEM"
	case EACCES:
		return "EACCES"
	case EFAULT:
		return "EFAULT"
	case ENOTBLK:
		return "ENOTBLK"
	case EBUSY:
		return "EBUSY"
	case EEXIST:
		return "EEXIST"
	case EXDEV:
		return "EXDEV"
	case ENODEV:
		return "ENODEV"
	case ENOTDIR:
		return "ENOTDIR"
	case EISDIR:
		return "EISDIR"
	case EINVAL:
		return "EINVAL"
	case ENFILE:
		return "ENFILE"
	case EMFILE:
		return "EMFILE"
	case ENOTTY:
		return "ENOTTY"
	case ETXTBSY:
		return "ETXTBSY"
	case EFBIG:
		return "EFBIG"
	case ENOSPC:
		return "ENOSPC"
	case ESPIPE:
		return "ESPIPE"
	case EROFS:
		return "EROFS"
	case EMLINK:
		return "EMLINK"
	case EPIPE:
		return "EPIPE"
	case EDOM:
		return "EDOM"
	case ERANGE:
		return "ERANGE"
	case EDEADLK:
		return "EDEADLK"
	case ENAMETOOLONG:
		return "ENAMETOOLONG"
	case ENOLCK:
		return "ENOLCK"
	case ENOSYS:
		return "ENOSYS"
	case ENOTEMPTY:
		return "ENOTEMPTY"
	case ELOOP:
		return "ELOOP"
	case ENOMSG:
		return "ENOMSG"
	case EIDRM:
		return "EIDRM"
	case ECHRNG:
		return "ECHRNG"
	case EL2NSYNC:
		return "EL2NSYNC"
	case EL3HLT:
		return "EL3HLT"
	case EL3RST:
		return "EL3RST"
	case ELNRNG:
		return "ELNRNG"
	case EUNATCH:
		return "EUNATCH"
	case ENOCSI:
		return "ENOCSI"
	case EL2HLT:
		return "EL2HLT"
	case EBADE:
		return "EBADE"
	case EBADR:
		return "EBADR"
	case EXFULL:
		return "EXFULL"
	case ENOANO:
		return "ENOANO"
	case EBADRQC:
		return "EBADRQC"
	case EBADSLT:
		return "EBADSLT"
	case EBFONT:
		return "EBFONT"
	case ENOSTR:
		return "ENOSTR"
	case ENODATA:
		return "ENODATA"
	case ETIME:
		return "ETIME"
	case ENOSR:
		return "ENOSR"
	case ENONET:
		return "ENONET"
	case ENOPKG:
		return "ENOPKG"
	case EREMOTE:
		return "EREMOTE"
	case ENOLINK:
		return "ENOLINK"
	case EADV:
		return "EADV"
	case ESRMNT:
		return "ESRMNT"
	case ECOMM:
		return "ECOMM"
	case EPROTO:
		return "EPROTO"
	case EMULTIHOP:
		return "EMULTIHOP"
	case EDOTDOT:
		return "EDOTDOT"
	case EBADMSG:
		return "EBADMSG"
	case EOVERFLOW:
		return "EOVERFLOW"
	case ENOTUNIQ:
		return "ENOTUNIQ"
	case EBADFD:
		return "EBADFD"
	case EREMCHG:
		return "EREMCHG"
	case ELIBACC:
		return "ELIBACC"
	case ELIBBAD:
		return "ELIBBAD"
	case ELIBSCN:
		return "ELIBSCN"
	case ELIBMAX:
		return "ELIBMAX"
	case ELIBEXEC:
		return "ELIBEXEC"
	case EILSEQ:
		return "EILSEQ"
	case ERESTART:
		return "ERESTART"
	case ESTRPIPE:
		return "ESTRPIPE"
	case EUSERS:
		return "EUSERS"
	case ENOTSOCK:
		return "ENOTSOCK"
	case EDESTADDRREQ:
		return "EDESTADDRREQ"
	case EMSGSIZE:
		return "EMSGSIZE"
	case EPROTOTYPE:
		return "EPROTOTYPE"
	case ENOPROTOOPT:
		return "ENOPROTOOPT"
	case EPROTONOSUPPORT:
		return "EPROTONOSUPPORT"
	case ESOCKTNOSUPPORT:
		return "ESOCKTNOSUPPORT"
	case EOPNOTSUPP:
		return "EOPNOTSUPP"
	case EPFNOSUPPORT:
		return "EPFNOSUPPORT"
	case EAFNOSUPPORT:
		return "EAFNOSUPPORT"
	case EADDRINUSE:
		return "EADDRINUSE"
	case EADDRNOTAVAIL:
		return "EADDRNOTAVAIL"
	case ENETDOWN:
		return "ENETDOWN"
	case ENETUNREACH:
		return "ENETUNREACH"
	case ENETRESET:
		return "ENETRESET"
	case ECONNABORTED:
		return "ECONNABORTED"
	case ECONNRESET:
		return "ECONNRESET"
	case ENOBUFS:
		return "ENOBUFS"
	case EISCONN:
		return "EISCONN"
	case ENOTCONN:
		return "ENOTCONN"
	case ESHUTDOWN:
		return "ESHUTDOWN"
	case ETOOMANYREFS:
		return "ETOOMANYREFS"
	case ETIMEDOUT:
		return "ETIMEDOUT"
	case ECONNREFUSED:
		return "ECONNREFUSED"
	case EHOSTDOWN:
		return "EHOSTDOWN"
	case EHOSTUNREACH:
		return "EHOSTUNREACH"
	case EALREADY:
		return "EALREADY"
	case EINPROGRESS:
		return "EINPROGRESS"
	case ESTALE:
		return "ESTALE"
	case EUCLEAN:
		return "EUCLEAN"
	case ENOTNAM:
		return "ENOTNAM"
	case ENAVAIL:
		return "ENAVAIL"
	case EISNAM:
		return "EISNAM"
	case EREMOTEIO:
		return "EREMOTEIO"
	case EDQUOT:
		return "EDQUOT"
	case ENOMEDIUM:
		return "ENOMEDIUM"
	case EMEDIUMTYPE:
		return "EMEDIUMTYPE"
	case ECANCELED:
		return "ECANCELED"
	case ENOKEY:
		return "ENOKEY"
	case EKEYEXPIRED:
		return "EKEYEXPIRED"
	case EKEYREVOKED:
		return "EKEYREVOKED"
	case EKEYREJECTED:
		return "EKEYREJECTED"
	case EOWNERDEAD:
		return "EOWNERDEAD"
	case ENOTRECOVERABLE:
		return "ENOTRECOVERABLE"
	case ERFKILL:
		return "ERFKILL"
	case EHWPOISON:
		return "EHWPOISON"
	case ERESTARTSYS:
		return "ERESTARTSYS"
	case ERESTARTNOINTR:
		return "ERESTARTNOINTR"
	case ERESTARTNOHAND:
		return "ERESTARTNOHAND"
	case ENOIOCTLCMD:
		return "ENOIOCTLCMD"
	case ERESTART_RESTARTBLOCK:
		return "ERESTART_RESTARTBLOCK"
	case EPROBE_DEFER:
		return "EPROBE_DEFER"
	case EOPENSTALE:
		return "EOPENSTALE"
	case ENOPARAM:
		return "ENOPARAM"
	case EBADHANDLE:
		return "EBADHANDLE"
	case ENOTSYNC:
		return "ENOTSYNC"
	case EBADCOOKIE:
		return "EBADCOOKIE"
	case ENOTSUPP:
		return "ENOTSUPP"
	case ETOOSMALL:
		return "ETOOSMALL"
	case ESERVERFAULT:
		return "ESERVERFAULT"
	case EBADTYPE:
		return "EBADTYPE"
	case EJUKEBOX:
		return "EJUKEBOX"
	case EIOCBQUEUED:
		return "EIOCBQUEUED"
	case ERECALLCONFLICT:
		return "ERECALLCONFLICT"
	default:
		return fmt.Sprintf("Err(%v)", input)
	}
}

// SetAttrFlag - Set Attr flag
type SetAttrFlag int32

const (
	// AttrMode - Mode changed
	AttrMode SetAttrFlag = 1 << 0
	// AttrUID - UID changed
	AttrUID SetAttrFlag = 1 << 1
	// AttrGID - GID changed
	AttrGID SetAttrFlag = 1 << 2
	// AttrSize - Size changed
	AttrSize SetAttrFlag = 1 << 3
	// AttrAtime - Atime changed
	AttrAtime SetAttrFlag = 1 << 4
	// AttrMtime - Mtime changed
	AttrMtime SetAttrFlag = 1 << 5
	// AttrCtime - Ctime changed
	AttrCtime SetAttrFlag = 1 << 6
	// AttrAtimeSet - ATimeSet
	AttrAtimeSet SetAttrFlag = 1 << 7
	// AttrMTimeSet - MTimeSet
	AttrMTimeSet SetAttrFlag = 1 << 8
	// AttrForce - Not a change, but a change it
	AttrForce SetAttrFlag = 1 << 9
	// AttrKillSUID - Kill SUID
	AttrKillSUID SetAttrFlag = 1 << 11
	// AttrKillSGID - Kill SGID
	AttrKillSGID SetAttrFlag = 1 << 12
	// AttrFile - File changed
	AttrFile SetAttrFlag = 1 << 13
	// AttrKillPriv - Fill Priv
	AttrKillPriv SetAttrFlag = 1 << 14
	// AttrOpen - Open
	AttrOpen SetAttrFlag = 1 << 15
	// AttrTimesSet - TimesSet
	AttrTimesSet SetAttrFlag = 1 << 16
	// AttrTouch - Touch
	AttrTouch SetAttrFlag = 1 << 17
)

// SetAttrFlagsToString - Returns the string list representation of SetAttr flags
func SetAttrFlagsToString(input uint32) []string {
	flag := SetAttrFlag(input)
	rep := []string{}
	if flag&AttrMode == AttrMode {
		rep = append(rep, "AttrMode")
	}
	if flag&AttrUID == AttrUID {
		rep = append(rep, "AttrUID")
	}
	if flag&AttrGID == AttrGID {
		rep = append(rep, "AttrGID")
	}
	if flag&AttrSize == AttrSize {
		rep = append(rep, "AttrSize")
	}
	if flag&AttrAtime == AttrAtime {
		rep = append(rep, "AttrAtime")
	}
	if flag&AttrMtime == AttrMtime {
		rep = append(rep, "AttrMtime")
	}
	if flag&AttrCtime == AttrCtime {
		rep = append(rep, "AttrCtime")
	}
	if flag&AttrAtimeSet == AttrAtimeSet {
		rep = append(rep, "AttrAtimeSet")
	}
	if flag&AttrMTimeSet == AttrMTimeSet {
		rep = append(rep, "AttrMTimeSet")
	}
	if flag&AttrForce == AttrForce {
		rep = append(rep, "AttrForce")
	}
	if flag&AttrKillSUID == AttrKillSUID {
		rep = append(rep, "AttrKillSUID")
	}
	if flag&AttrKillSGID == AttrKillSGID {
		rep = append(rep, "AttrKillSGID")
	}
	if flag&AttrFile == AttrFile {
		rep = append(rep, "AttrFile")
	}
	if flag&AttrKillPriv == AttrKillPriv {
		rep = append(rep, "AttrKillPriv")
	}
	if flag&AttrOpen == AttrOpen {
		rep = append(rep, "AttrOpen")
	}
	if flag&AttrTimesSet == AttrTimesSet {
		rep = append(rep, "AttrTimesSet")
	}
	if flag&AttrTouch == AttrTouch {
		rep = append(rep, "AttrTouch")
	}
	return rep
}

// OpenFlag - Open syscall flag
type OpenFlag int

const (
	OACCMODE   OpenFlag = 3
	ORDONLY    OpenFlag = 0
	OWRONLY    OpenFlag = 1
	ORDWR      OpenFlag = 2
	OCREAT     OpenFlag = 64
	OEXCL      OpenFlag = 128
	ONOCTTY    OpenFlag = 256
	OTRUNC     OpenFlag = 512
	OAPPEND    OpenFlag = 1024
	ONONBLOCK  OpenFlag = 2048
	ODSYNC     OpenFlag = 4096  /* used to be OSYNC, see below */
	FASYNC     OpenFlag = 8192  /* fcntl, for BSD compatibility */
	ODIRECT    OpenFlag = 16384 /* direct disk access hint */
	OLARGEFILE OpenFlag = 32768
	ODIRECTORY OpenFlag = 65536  /* must be a directory */
	ONOFOLLOW  OpenFlag = 131072 /* don't follow links */
	ONOATIME   OpenFlag = 262144
	OCLOEXEC   OpenFlag = 524288 /* set close_on_exec */
)

// OpenFlagsToStrings - Returns the string list version of flags
func OpenFlagsToStrings(input uint32) []string {
	flags := OpenFlag(input)
	rep := []string{}
	if flags&OACCMODE == OACCMODE {
		rep = append(rep, "OACCMODE")
	}
	if flags&ORDONLY == ORDONLY {
		rep = append(rep, "ORDONLY")
	}
	if flags&OWRONLY == OWRONLY {
		rep = append(rep, "OWRONLY")
	}
	if flags&ORDWR == ORDWR {
		rep = append(rep, "ORDWR")
	}
	if flags&OCREAT == OCREAT {
		rep = append(rep, "OCREAT")
	}
	if flags&OEXCL == OEXCL {
		rep = append(rep, "OEXCL")
	}
	if flags&ONOCTTY == ONOCTTY {
		rep = append(rep, "ONOCTTY")
	}
	if flags&OTRUNC == OTRUNC {
		rep = append(rep, "OTRUNC")
	}
	if flags&OAPPEND == OAPPEND {
		rep = append(rep, "OAPPEND")
	}
	if flags&ONONBLOCK == ONONBLOCK {
		rep = append(rep, "ONONBLOCK")
	}
	if flags&ODSYNC == ODSYNC {
		rep = append(rep, "ODSYNC")
	}
	if flags&FASYNC == FASYNC {
		rep = append(rep, "FASYNC")
	}
	if flags&ODIRECT == ODIRECT {
		rep = append(rep, "ODIRECT")
	}
	if flags&OLARGEFILE == OLARGEFILE {
		rep = append(rep, "OLARGEFILE")
	}
	if flags&ODIRECTORY == ODIRECTORY {
		rep = append(rep, "ODIRECTORY")
	}
	if flags&ONOFOLLOW == ONOFOLLOW {
		rep = append(rep, "ONOFOLLOW")
	}
	if flags&ONOATIME == ONOATIME {
		rep = append(rep, "ONOATIME")
	}
	if flags&OCLOEXEC == OCLOEXEC {
		rep = append(rep, "OCLOEXEC")
	}
	return rep
}
