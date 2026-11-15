package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const testDatasetHex = "0e080000000000010000000300000f0208dead00beef00cafe051000112233445566778899aabbccddeeff01021234"

func TestReachFlags(t *testing.T) {
	t.Setenv("TMCTL_WIFI_PASSWORD", "from-env1")
	t.Setenv("TMCTL_THREAD_DATASET", "")
	parse := func(network bool, args ...string) (bool, []byte, []byte, []byte, string, error) {
		fs := flagSet("test")
		fs.SetOutput(io.Discard)
		rf := addReachFlags(fs, network)
		pos, err := parseArgs(fs, args)
		if err != nil {
			return false, nil, nil, nil, "", err
		}
		opts, err := rf.options(pos)
		var ssid, pw []byte
		if opts.WiFi != nil {
			ssid, pw = opts.WiFi.SSID, opts.WiFi.Password
		}
		addr := ""
		if opts.Addr.IsValid() {
			addr = opts.Addr.String()
		}
		return opts.BLE, ssid, pw, opts.Thread, addr, err
	}

	// Nothing: found wherever it is, given no network.
	if ble, ssid, _, ds, addr, err := parse(true); err != nil || ble || ssid != nil || ds != nil || addr != "" {
		t.Errorf("no flags: ble %v ssid %q dataset %x addr %q err %v", ble, ssid, ds, addr, err)
	}
	// Wi-Fi without -ble: the transport is chosen when the device is found.
	if ble, ssid, pw, _, _, err := parse(true, "-ssid", "home", "-password", "secret123"); err != nil || ble ||
		string(ssid) != "home" || string(pw) != "secret123" {
		t.Errorf("-ssid: ble %v ssid %q pw %q err %v", ble, ssid, pw, err)
	}
	if _, _, pw, _, _, err := parse(true, "-ssid", "home"); err != nil || string(pw) != "from-env1" {
		t.Errorf("password from the environment: %q, %v", pw, err)
	}
	// An address with a network: only with -ble, where it is the address
	// the device will have.
	if ble, _, _, _, addr, err := parse(true, "-ble", "-ssid", "home", "192.168.1.5"); err != nil || !ble ||
		addr != "192.168.1.5:5540" {
		t.Errorf("-ble with address: ble %v addr %q err %v", ble, addr, err)
	}
	if _, _, _, ds, _, err := parse(true, "-thread", "-dataset", testDatasetHex); err != nil || len(ds) != len(testDatasetHex)/2 {
		t.Errorf("-thread: dataset %x err %v", ds, err)
	}
	t.Setenv("TMCTL_THREAD_DATASET", " "+testDatasetHex+"\n")
	if _, _, _, ds, _, err := parse(true, "-thread"); err != nil || !bytes.Equal(ds[:2], []byte{0x0e, 0x08}) {
		t.Errorf("dataset from the environment: %x, %v", ds, err)
	}
	t.Setenv("TMCTL_THREAD_DATASET", "")

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-ssid", "home", "-thread", "-dataset", testDatasetHex}, "not both"},
		{[]string{"-password", "secret123"}, "-password without -ssid"},
		{[]string{"-dataset", testDatasetHex}, "-dataset without -thread"},
		{[]string{"-thread"}, "-thread needs -dataset"},
		{[]string{"-thread", "-dataset", "0e0z"}, "Thread dataset"},
		{[]string{"-ssid", "home", "192.168.1.5"}, "add -ble"},
	} {
		if _, _, _, _, _, err := parse(true, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.args, err, tc.want)
		}
	}
	// scan has no network flags.
	if _, _, _, _, _, err := parse(false, "-ssid", "home"); err == nil {
		t.Error("scan -ssid: no error")
	}
	if ble, _, _, _, addr, err := parse(false, "-ble", "[fe80::1%lo]:5540"); err != nil || !ble || addr != "[fe80::1%lo]:5540" {
		t.Errorf("scan -ble address: ble %v addr %q err %v", ble, addr, err)
	}
}
