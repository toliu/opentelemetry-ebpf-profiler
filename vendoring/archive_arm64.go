package vendoring

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed archive/arm64
var archive embed.FS

func Open(filename string) (fs.File, error) {
	return archive.Open(fmt.Sprintf("archive/arm64/%s", filename))
}
