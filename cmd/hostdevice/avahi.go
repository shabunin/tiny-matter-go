package main

import (
	"log"

	"github.com/shabunin/tiny-matter-go/internal/avahi"
)

// avahiAdvertiser publishes the device's services with avahi-publish.
type avahiAdvertiser struct{ avahi.Advertiser }

func newAvahiAdvertiser() *avahiAdvertiser {
	return &avahiAdvertiser{avahi.Advertiser{Log: func(msg string) { log.Print(msg) }}}
}

// avahiResolver finds other nodes with avahi-browse.
type avahiResolver struct{ avahi.Resolver }
