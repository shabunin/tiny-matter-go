package im

import "github.com/shabunin/tiny-matter-go/tlv"

// Client-side message codecs, for controllers and tests.

// EncodeReadRequest encodes a ReadRequest for paths.
func EncodeReadRequest(paths []AttributePath, fabricFiltered bool) []byte {
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.StartArray(tlv.ContextTag(0))
	for _, p := range paths {
		EncodeAttributePath(w, tlv.Anonymous, p)
	}
	w.EndContainer()
	w.PutBool(tlv.ContextTag(3), fabricFiltered)
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	return w.Bytes()
}

// EncodeStatusResponse encodes a StatusResponse.
func EncodeStatusResponse(s Status) []byte {
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(0), uint64(s))
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	return w.Bytes()
}

// DecodeStatusResponse decodes a StatusResponse.
func DecodeStatusResponse(b []byte) (Status, error) { return decodeStatusResponse(b) }

// EncodeTimedRequest encodes a TimedRequest.
func EncodeTimedRequest(timeoutMs uint16) []byte {
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(0), uint64(timeoutMs))
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	return w.Bytes()
}

// EncodeInvokeRequest encodes an InvokeRequest of one command. fields, if
// not nil, writes the command fields (context tags) into the open structure.
func EncodeInvokeRequest(p CommandPath, timed bool, fields func(w *tlv.Writer)) []byte {
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.PutBool(tlv.ContextTag(0), false)
	w.PutBool(tlv.ContextTag(1), timed)
	w.StartArray(tlv.ContextTag(2))
	w.StartStruct(tlv.Anonymous)
	EncodeCommandPath(w, tlv.ContextTag(0), p)
	w.StartStruct(tlv.ContextTag(1))
	if fields != nil {
		fields(w)
	}
	w.EndContainer()
	w.EndContainer()
	w.EndContainer()
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	return w.Bytes()
}

// EncodeWriteRequest encodes a WriteRequest of one attribute. value writes
// the value with the given tag.
func EncodeWriteRequest(p AttributePath, timed bool, value func(w *tlv.Writer, tag tlv.Tag)) []byte {
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.PutBool(tlv.ContextTag(0), false)
	w.PutBool(tlv.ContextTag(1), timed)
	w.StartArray(tlv.ContextTag(2))
	w.StartStruct(tlv.Anonymous)
	EncodeAttributePath(w, tlv.ContextTag(1), p)
	value(w, tlv.ContextTag(2))
	w.EndContainer()
	w.EndContainer()
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	return w.Bytes()
}

// AttributeReport is one report from a ReportData message.
type AttributeReport struct {
	Path        AttributePath
	Status      Status
	DataVersion uint32
	Data        []byte // raw TLV element (anonymous-tagged value not guaranteed)
}

// ReportData is a decoded ReportData message.
type ReportData struct {
	SubscriptionID   uint32
	Reports          []AttributeReport
	MoreChunks       bool
	SuppressResponse bool
}

// DecodeReportData decodes a ReportData message. Report data aliases b.
func DecodeReportData(b []byte) (*ReportData, error) {
	rd := &ReportData{}
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			rd.SubscriptionID, err = r.Uint32()
		case 1:
			return arrayItems(r, func() error {
				var rep AttributeReport
				err := structFields(r, func(r *tlv.Reader, tag uint8) error {
					return structFields(r, func(r *tlv.Reader, f uint8) (err error) {
						switch {
						case tag == 0 && f == 0, tag == 1 && f == 1:
							rep.Path, err = DecodeAttributePath(r)
						case tag == 0 && f == 1:
							rep.Status, _, _, err = DecodeStatusIB(r)
						case tag == 1 && f == 0:
							rep.DataVersion, err = r.Uint32()
						case tag == 1 && f == 2:
							rep.Data, err = r.RawElement()
						}
						return err
					})
				})
				rd.Reports = append(rd.Reports, rep)
				return err
			})
		case 3:
			rd.MoreChunks, err = r.Bool()
		case 4:
			rd.SuppressResponse, err = r.Bool()
		}
		return err
	})
	return rd, err
}

// InvokeResult is one InvokeResponseIB.
type InvokeResult struct {
	Path   CommandPath
	Status Status
	// ClusterStatus is the cluster-specific status, if HasClusterStatus.
	ClusterStatus    uint8
	HasClusterStatus bool
	Fields           []byte // raw response fields structure, if a command was returned
}

// DecodeInvokeResponse decodes an InvokeResponse message.
func DecodeInvokeResponse(b []byte) ([]InvokeResult, error) {
	var out []InvokeResult
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) error {
		if tag != 1 {
			return nil
		}
		return arrayItems(r, func() error {
			var res InvokeResult
			err := structFields(r, func(r *tlv.Reader, tag uint8) error {
				return structFields(r, func(r *tlv.Reader, f uint8) (err error) {
					switch {
					case f == 0:
						res.Path, err = DecodeCommandPath(r)
					case tag == 0 && f == 1:
						res.Fields, err = r.RawElement()
					case tag == 1 && f == 1:
						res.Status, res.ClusterStatus, res.HasClusterStatus, err = DecodeStatusIB(r)
					}
					return err
				})
			})
			out = append(out, res)
			return err
		})
	})
	return out, err
}

// DecodeWriteResponse decodes a WriteResponse into per-path statuses.
func DecodeWriteResponse(b []byte) ([]AttributeReport, error) {
	var out []AttributeReport
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) error {
		if tag != 0 {
			return nil
		}
		return arrayItems(r, func() error {
			var rep AttributeReport
			err := structFields(r, func(r *tlv.Reader, f uint8) (err error) {
				switch f {
				case 0:
					rep.Path, err = DecodeAttributePath(r)
				case 1:
					rep.Status, _, _, err = DecodeStatusIB(r)
				}
				return err
			})
			out = append(out, rep)
			return err
		})
	})
	return out, err
}

// EncodeSubscribeRequest encodes a SubscribeRequest for paths with the
// given interval bounds in seconds.
func EncodeSubscribeRequest(paths []AttributePath, minFloor, maxCeiling uint16, keep, fabricFiltered bool) []byte {
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.PutBool(tlv.ContextTag(0), keep)
	w.PutUint(tlv.ContextTag(1), uint64(minFloor))
	w.PutUint(tlv.ContextTag(2), uint64(maxCeiling))
	w.StartArray(tlv.ContextTag(3))
	for _, p := range paths {
		EncodeAttributePath(w, tlv.Anonymous, p)
	}
	w.EndContainer()
	w.PutBool(tlv.ContextTag(7), fabricFiltered)
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	return w.Bytes()
}

// DecodeSubscribeResponse returns the subscription ID and max interval
// (seconds) of a SubscribeResponse.
func DecodeSubscribeResponse(b []byte) (id uint32, maxInterval uint16, err error) {
	err = structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			id, err = r.Uint32()
		case 2:
			maxInterval, err = r.Uint16()
		}
		return err
	})
	return id, maxInterval, err
}
