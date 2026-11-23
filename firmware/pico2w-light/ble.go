package main

import (
	"time"

	"firmware/cyw43wifi"
	"firmware/matterble"
	"firmware/wifinode"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/device"
	"tinygo.org/x/bluetooth/hci"
)

// writeBDAddr is the Broadcom vendor command (OCF) that sets the
// controller's public address until its next reset.
const writeBDAddr = 0x0001

// commissionOverBLE advertises the Matter BLE service and serves the
// commissioner over BTP until it provisions a network with ConnectNetwork,
// then closes the BLE link and returns the network to join. poll runs the
// rest of the firmware (LED, console, watchdog heartbeat) meanwhile.
func commissionOverBLE(d *device.Device, tr *wifinode.Transport, mac [6]byte, poll func(now time.Time)) clusters.WiFiNetwork {
	src, err := radio.Dev.HCIReadWriter()
	if err != nil {
		fatal("bluetooth", err)
	}
	addr := cyw43wifi.BDAddr(mac)
	matterble.Log = func(msg string) { println(msg) }
	b, err := matterble.New(matterble.NewTransport(src), discriminator, devcreds.VendorID, devcreds.ProductID, matterble.Options{
		// A notification must fit the driver's HCI write: MTU + 9 bytes.
		MTU: cyw43wifi.HCIMaxPacket - 9,
		Setup: func(h *hci.HCI) error {
			var le [6]byte
			for i := range addr {
				le[i] = addr[5-i]
			}
			return h.SendVendorCommand(writeBDAddr, le[:])
		},
	})
	if err != nil {
		fatal("ble", err)
	}
	tr.Link = b
	var join *clusters.WiFiNetwork
	d.Net.Connect = func(now time.Time, n clusters.WiFiNetwork) {
		println("ConnectNetwork: closing BLE, joining the network")
		join = &n
		b.Close(now)
	}
	d.HoldSaves = true // a flash erase stops the CPU; keep it off the link
	println("BLE advertising as", wifinode.HexMAC(addr), "discriminator", discriminator)
	for {
		now := time.Now()
		b.Poll(now, func(msg []byte) {
			if err := d.HandlePacket(now, matterble.Peer, msg); err != nil {
				println("ble drop:", err.Error())
			}
		})
		d.Poll(now)
		if join != nil && !b.Connected() {
			break
		}
		b.Advertise(!b.Connected() && join == nil && d.PASE.WindowOpen())
		poll(now)
		time.Sleep(2 * time.Millisecond)
	}
	b.Advertise(false)
	d.HoldSaves = false
	tr.Link = nil
	d.Net.Connect = nil
	return *join
}
