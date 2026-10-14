package version

import "runtime/debug"

var Version = "dev"

func Get() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		v := bi.Main.Version
		if v != "" && v != "(devel)" {
			return v
		}
	}
	return Version
}
