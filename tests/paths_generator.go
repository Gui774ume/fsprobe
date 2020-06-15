package tests

import (
	"math/rand"
	"os"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}

// PathsGenerator - Paths generator used for the benchmark
type PathsGenerator struct {
	WatchEntireFilesystem bool
	OutOfScope            bool
	Depth                 int
	Breadth               int
	NumOfFiles            int
	NamesLength           int
	Root                  string
	folders               []string
	files                 []string
}

func (pg *PathsGenerator) Init() error {
	if err := pg.CreateFolders(); err != nil {
		return err
	}
	if err := pg.CreateFiles(); err != nil {
		return err
	}
	return nil
}

func (pg *PathsGenerator) GetWatchedPaths() []string {
	if pg.WatchEntireFilesystem {
		return []string{}
	}
	if pg.OutOfScope {
		// Return a directory. Hopefully this will not be Root, we just want to benchmark the overhead on files that
		// are not watched.
		return []string{"/boot"}
	}
	return []string{pg.Root}
}

func (pg *PathsGenerator) CreateFolders() error {
	var pathTmp string
	for i := 0; i < pg.Breadth; i++ {
		pathTmp = pg.Root
		for j := 0; j < pg.Depth; j++ {
			pathTmp += "/" + RandomString(pg.NamesLength)
		}
		// Create folder
		if err := os.MkdirAll(pathTmp, 0644); err != nil {
			return err
		}
		pg.folders = append(pg.folders, pathTmp)
	}
	return nil
}

func (pg *PathsGenerator) CreateFiles() error {
	var pathTmp string
	for i := 0; i < pg.NumOfFiles; i++ {
		pathTmp = pg.folders[i%pg.Breadth]
		pathTmp += "/" + RandomString(pg.NamesLength)
		f, err := os.OpenFile(pathTmp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		pg.files = append(pg.files, pathTmp)
	}
	return nil
}

func (pg *PathsGenerator) GetRandomFile() string {
	return pg.files[rand.Intn(pg.NumOfFiles)]
}

// Close - Delete all generated files and folders
func (pg *PathsGenerator) Close() error {
	return os.RemoveAll(pg.Root)
}
