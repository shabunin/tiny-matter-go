//go:build !esp32s3

package espota

func hwFlashRead(addr uint32, p []uint32) error                 { return errFlash }
func hwFlashWrite(addr uint32, p []uint32) error                { return errFlash }
func hwWriteSector(addr uint32, data *[sector / 4]uint32) error { return errFlash }
func hwRunningBase() uint32                                     { return 0 }
