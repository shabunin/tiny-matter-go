//go:build !esp32s3 && !esp32

package espota

const (
	SlotA = 0x10000
	SlotB = 0x200000
)

var defaultLayout = layoutESP32S3

func hwFlashRead(addr uint32, p []uint32) error                 { return errFlash }
func hwFlashWrite(addr uint32, p []uint32) error                { return errFlash }
func hwWriteSector(addr uint32, data *[sector / 4]uint32) error { return errFlash }
func hwRunningBase() uint32                                     { return 0 }
