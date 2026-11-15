package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/datamodel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

var statusNames = map[im.Status]string{
	0x00: "Success", 0x01: "Failure", 0x7D: "InvalidSubscription", 0x7E: "UnsupportedAccess",
	0x7F: "UnsupportedEndpoint", 0x80: "InvalidAction", 0x81: "UnsupportedCommand", 0x85: "InvalidCommand",
	0x86: "UnsupportedAttribute", 0x87: "ConstraintError", 0x88: "UnsupportedWrite", 0x89: "ResourceExhausted",
	0x8B: "NotFound", 0x8C: "UnreportableAttribute", 0x8D: "InvalidDataType", 0x8F: "UnsupportedRead",
	0x92: "DataVersionMismatch", 0x94: "Timeout", 0x9C: "Busy", 0x9D: "AccessRestricted",
	0xC3: "UnsupportedCluster", 0xC5: "NoUpstreamSubscription", 0xC6: "NeedsTimedInteraction",
	0xC7: "UnsupportedEvent", 0xC8: "PathsExhausted", 0xC9: "TimedRequestMismatch", 0xCA: "FailsafeRequired",
	0xCB: "InvalidInState", 0xCC: "NoCommandResponse",
}

func statusString(s im.Status) string {
	if name, ok := statusNames[s]; ok {
		return fmt.Sprintf("%s (%#02x)", name, uint8(s))
	}
	return fmt.Sprintf("status %#02x", uint8(s))
}

// describe names the Interaction Model status of an error.
func describe(err error) error {
	var st im.Status
	var ce *controller.CommandError
	var inner error
	var msg string
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ce):
		inner, msg = ce, statusString(ce.Status)
		if ce.HasClusterStatus {
			msg = fmt.Sprintf("%s, cluster status %d", msg, ce.ClusterStatus)
		}
	case errors.As(err, &st):
		inner, msg = st, statusString(st)
	default:
		return err
	}
	// Keep the context wrapped around the status ("AddGroup: ...").
	return errors.New(strings.TrimSuffix(err.Error(), inner.Error()) + msg)
}

func pathName(ep uint16, cluster, member uint32, kind string) (string, *datamodel.Cluster) {
	cl := model().ClusterByID(cluster)
	cname := fmt.Sprintf("0x%04X", cluster)
	if cl != nil {
		cname = cl.Name
	}
	mname := fmt.Sprintf("0x%04X", member)
	if cl != nil {
		switch kind {
		case "attribute":
			if a := cl.AttributeByID(member); a != nil {
				mname = a.Name
			}
		case "event":
			if e := cl.EventByID(member); e != nil {
				mname = e.Name
			}
		}
	}
	return fmt.Sprintf("%d/%s/%s", ep, cname, mname), cl
}

// attributeLines formats attribute reports, joining lists a device sent
// in pieces (a list, then items appended to it).
func attributeLines(reports []im.AttributeReport) []string {
	type value struct {
		path   im.AttributePath
		status im.Status
		field  *datamodel.Field
		data   []byte   // a scalar or struct
		items  [][]byte // a list's items
		isList bool
	}
	var values []*value
	find := func(p im.AttributePath) *value {
		for i := len(values) - 1; i >= 0; i-- {
			v := values[i]
			if v.isList && v.path.Endpoint == p.Endpoint && v.path.Cluster == p.Cluster && v.path.Attribute == p.Attribute {
				return v
			}
		}
		return nil
	}
	for _, a := range reports {
		var f *datamodel.Field
		if cl := model().ClusterByID(a.Path.Cluster); cl != nil {
			if attr := cl.AttributeByID(a.Path.Attribute); attr != nil {
				f = &attr.Field
			}
		}
		if a.Path.ListAppend {
			if v := find(a.Path); v != nil {
				v.items = append(v.items, a.Data)
				continue
			}
		}
		v := &value{path: a.Path, status: a.Status, field: f, data: a.Data}
		if a.Status == im.Success {
			r := tlv.NewReader(a.Data)
			if r.Next() == nil && (r.Type() == tlv.TypeArray || r.Type() == tlv.TypeList) && r.EnterContainer() == nil {
				v.isList, v.data = true, nil
				for r.Next() == nil {
					raw, err := r.RawElement()
					if err != nil {
						break
					}
					v.items = append(v.items, raw)
				}
			}
		}
		values = append(values, v)
	}
	var lines []string
	for _, v := range values {
		name, _ := pathName(v.path.Endpoint, v.path.Cluster, v.path.Attribute, "attribute")
		switch {
		case v.status != im.Success:
			lines = append(lines, name+": "+statusString(v.status))
		case v.isList:
			var item *datamodel.Field
			if v.field != nil {
				f := *v.field
				f.List = false
				item = &f
			}
			parts := make([]string, len(v.items))
			for i, it := range v.items {
				parts[i] = datamodel.Format(it, item)
			}
			lines = append(lines, name+" = ["+strings.Join(parts, ", ")+"]")
		default:
			lines = append(lines, name+" = "+datamodel.Format(v.data, v.field))
		}
	}
	return lines
}

var priorities = [...]string{"debug", "info", "critical"}

// eventLines formats event reports.
func eventLines(events []im.EventReport) []string {
	var lines []string
	var last uint64
	for _, e := range events {
		name, cl := pathName(e.Path.Endpoint, e.Path.Cluster, e.Path.Event, "event")
		if e.Status != im.Success {
			lines = append(lines, name+": "+statusString(e.Status))
			continue
		}
		ts := e.Timestamp
		if e.Delta {
			ts += last
		}
		last = ts
		when := time.UnixMilli(int64(ts)).Local().Format("2006-01-02 15:04:05.000")
		if e.System {
			when = fmt.Sprintf("boot+%.3fs", float64(ts)/1000)
		}
		prio := fmt.Sprint(e.Priority)
		if int(e.Priority) < len(priorities) {
			prio = priorities[e.Priority]
		}
		var fields []*datamodel.Field
		if cl != nil {
			if ev := cl.EventByID(e.Path.Event); ev != nil {
				fields = ev.Fields
			}
		}
		data := "{}"
		if len(e.Data) > 0 {
			data = datamodel.FormatFields(e.Data, fields)
		}
		lines = append(lines, fmt.Sprintf("#%d %s %s %s %s", e.Number, when, prio, name, data))
	}
	return lines
}
