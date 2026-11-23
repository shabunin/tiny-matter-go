module firmware

go 1.25.0

require (
	github.com/shabunin/tiny-matter-go v0.0.0
	github.com/soypat/cyw43439 v0.2.0
	tinygo.org/x/bluetooth v0.17.0
	tinygo.org/x/espradio v0.5.0
)

require (
	github.com/soypat/seqs v0.0.0-20260125140838-2c1c6b1bd69e // indirect
	github.com/tinygo-org/pio v0.3.0 // indirect
	golang.org/x/exp v0.0.0-20260727155853-b88d891fe743 // indirect
)

require (
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/soypat/lneto v0.4.0 // indirect
	tinygo.org/x/drivers v0.37.0 // indirect
)

replace github.com/shabunin/tiny-matter-go => ../

replace github.com/soypat/cyw43439 => github.com/shabunin/cyw43439 v0.0.0-20261123193914-7c3305b89fc4
