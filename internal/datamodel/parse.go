package datamodel

import (
	"fmt"
	"sort"
	"strings"
)

// The IDL (Matter SDK scripts/py_matter_idl) as far as cluster
// definitions go:
//
//	[shared] enum Name : enum8 { kItem = 1; ... }
//	[shared] bitmap Name : bitmap8 { kBit = 0x1; ... }
//	[shared|fabric_scoped|request|response] struct Name [= id] { fields }
//	[provisional|internal|...] cluster Name = id {
//	  revision n;
//	  [readonly|fixed|...] attribute [access(...)] field
//	  [timed] [fabric] command [access(...)] Name([Request]): Response = id;
//	  [fabric_sensitive] critical|info|debug event [access(...)] Name = id { fields }
//	}
//
// where a field is
//
//	[optional] [nullable] [fabric_sensitive] type[<max>] name[[]] = id;

type token struct {
	kind byte // 'i' identifier, 'n' number, 's' string, 'p' punctuation, 0 end
	s    string
	line int
}

type parser struct {
	src  string
	pos  int
	line int
	tok  token
	doc  string // the last doc comment
	m    *Model
}

// Parse parses cluster definitions in the IDL.
func Parse(src string) (m *Model, err error) {
	p := &parser{src: src, line: 1, m: &Model{types: map[string]*Type{}, prims: map[string]*Type{}, byID: map[uint32]*Cluster{}}}
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(parseError)
			if !ok {
				panic(r)
			}
			m, err = nil, e
		}
	}()
	p.next()
	for p.tok.kind != 0 {
		doc := p.takeDoc()
		quals := p.qualifiers()
		switch kw := p.ident(); kw {
		case "enum", "bitmap":
			t := p.enum(kw)
			p.m.types[t.Name] = t
		case "struct":
			t, _ := p.strct(quals)
			p.m.types[t.Name] = t
		case "cluster":
			c := p.cluster(doc)
			p.m.Clusters = append(p.m.Clusters, c)
			if _, dup := p.m.byID[c.ID]; !dup {
				p.m.byID[c.ID] = c
			}
		default:
			p.fail("unexpected %q", kw)
		}
	}
	for _, c := range p.m.Clusters {
		if err := p.m.resolve(c); err != nil {
			return nil, err
		}
	}
	for _, t := range p.m.types {
		for _, f := range t.Fields {
			if f.Type = p.m.lookup(nil, f.typeName); f.Type == nil {
				return nil, fmt.Errorf("unknown type %q in %s", f.typeName, t.Name)
			}
		}
	}
	return p.m, nil
}

type parseError string

func (e parseError) Error() string { return string(e) }

func (p *parser) fail(format string, args ...any) {
	panic(parseError(fmt.Sprintf("line %d: ", p.tok.line) + fmt.Sprintf(format, args...)))
}

// next reads the next token, recording doc comments.
func (p *parser) next() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '\n':
			p.line++
			p.pos++
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
		case strings.HasPrefix(p.src[p.pos:], "//"):
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case strings.HasPrefix(p.src[p.pos:], "/*"):
			end := strings.Index(p.src[p.pos+2:], "*/")
			if end < 0 {
				p.fail("unterminated comment")
			}
			text := p.src[p.pos : p.pos+2+end+2]
			p.line += strings.Count(text, "\n")
			p.pos += len(text)
			if strings.HasPrefix(text, "/**") {
				p.doc = cleanDoc(text[3 : len(text)-2])
			}
		default:
			start, line := p.pos, p.line
			switch {
			case isIdentStart(c):
				for p.pos < len(p.src) && isIdent(p.src[p.pos]) {
					p.pos++
				}
				p.tok = token{'i', p.src[start:p.pos], line}
			case c == '"':
				end := strings.IndexByte(p.src[p.pos+1:], '"')
				if end < 0 {
					p.fail("unterminated string")
				}
				p.pos += end + 2
				p.tok = token{'s', p.src[start+1 : p.pos-1], line}
			case c >= '0' && c <= '9':
				for p.pos < len(p.src) && isIdent(p.src[p.pos]) {
					p.pos++
				}
				p.tok = token{'n', p.src[start:p.pos], line}
			default:
				p.pos++
				p.tok = token{'p', p.src[start:p.pos], line}
			}
			return
		}
	}
	p.tok = token{0, "", p.line}
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdent(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

func cleanDoc(s string) string {
	var words []string
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "*")
		words = append(words, strings.Fields(line)...)
	}
	return strings.Join(words, " ")
}

func (p *parser) takeDoc() string {
	d := p.doc
	p.doc = ""
	return d
}

func (p *parser) ident() string {
	if p.tok.kind != 'i' {
		p.fail("want an identifier, have %q", p.tok.s)
	}
	s := p.tok.s
	p.next()
	return s
}

func (p *parser) number() uint64 {
	if p.tok.kind != 'n' {
		p.fail("want a number, have %q", p.tok.s)
	}
	n, ok := number(p.tok.s)
	if !ok {
		p.fail("bad number %q", p.tok.s)
	}
	p.next()
	return n
}

func (p *parser) expect(punct string) {
	if p.tok.kind != 'p' || p.tok.s != punct {
		p.fail("want %q, have %q", punct, p.tok.s)
	}
	p.next()
}

func (p *parser) is(punct string) bool { return p.tok.kind == 'p' && p.tok.s == punct }

var keywords = map[string]bool{
	"enum": true, "bitmap": true, "struct": true, "cluster": true,
	"attribute": true, "command": true, "event": true, "revision": true,
}

// qualifiers reads the words before a keyword.
func (p *parser) qualifiers() map[string]bool {
	q := map[string]bool{}
	for p.tok.kind == 'i' && !keywords[p.tok.s] {
		q[p.ident()] = true
	}
	return q
}

// access skips an access(...) clause.
func (p *parser) access() {
	if p.tok.kind == 'i' && p.tok.s == "access" {
		p.next()
		p.expect("(")
		for !p.is(")") {
			if p.tok.kind == 0 {
				p.fail("unterminated access clause")
			}
			p.next()
		}
		p.next()
	}
}

func (p *parser) enum(kw string) *Type {
	t := &Type{Name: p.ident(), Kind: KindEnum}
	if kw == "bitmap" {
		t.Kind = KindBitmap
	}
	p.expect(":")
	t.Base = p.ident()
	p.expect("{")
	for !p.is("}") {
		p.takeDoc()
		name := p.ident()
		p.expect("=")
		t.Items = append(t.Items, Item{Name: itemName(name), Value: p.number()})
		if p.is("[") { // annotations, such as [spec_name = "..."]
			for !p.is("]") {
				if p.tok.kind == 0 {
					p.fail("unterminated annotation")
				}
				p.next()
			}
			p.next()
		}
		p.expect(";")
	}
	p.next()
	return t
}

// itemName drops the "k" the IDL puts before enum and bitmap names.
func itemName(s string) string {
	if len(s) > 1 && s[0] == 'k' && (s[1] >= 'A' && s[1] <= 'Z' || s[1] >= '0' && s[1] <= '9') {
		return s[1:]
	}
	return s
}

// strct parses a struct; it returns the response command ID of a
// response struct.
func (p *parser) strct(quals map[string]bool) (*Type, uint32) {
	t := &Type{Name: p.ident(), Kind: KindStruct, FabricScoped: quals["fabric_scoped"]}
	var id uint32
	if p.is("=") {
		p.next()
		id = uint32(p.number())
	}
	t.Fields = p.fields()
	return t, id
}

func (p *parser) fields() []*Field {
	p.expect("{")
	var out []*Field
	for !p.is("}") {
		p.takeDoc()
		out = append(out, p.field())
	}
	p.next()
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (p *parser) field() *Field {
	f := &Field{}
quals:
	for p.tok.kind == 'i' {
		switch p.tok.s {
		case "optional":
			f.Optional = true
		case "nullable":
			f.Nullable = true
		case "fabric_sensitive":
		default:
			break quals
		}
		p.next()
	}
	f.typeName = p.ident()
	if p.is("<") {
		for !p.is(">") {
			if p.tok.kind == 0 {
				p.fail("unterminated type length")
			}
			p.next()
		}
		p.next()
	}
	f.Name = p.ident()
	if p.is("[") {
		p.next()
		p.expect("]")
		f.List = true
	}
	p.expect("=")
	f.ID = uint32(p.number())
	p.expect(";")
	return f
}

func (p *parser) cluster(doc string) *Cluster {
	c := &Cluster{Name: p.ident(), Doc: doc, types: map[string]*Type{}}
	p.expect("=")
	c.ID = uint32(p.number())
	p.expect("{")
	for !p.is("}") {
		doc := p.takeDoc()
		quals := p.qualifiers()
		switch kw := p.ident(); kw {
		case "revision":
			c.Revision = int(p.number())
			p.expect(";")
		case "enum", "bitmap":
			t := p.enum(kw)
			c.types[t.Name] = t
		case "struct":
			t, id := p.strct(quals)
			c.types[t.Name] = t
			if quals["response"] {
				t.Items = []Item{{Value: uint64(id)}} // the ID, until resolved
			}
		case "attribute":
			p.access()
			a := &Attribute{Field: *p.field(), Doc: doc}
			a.Writable = !quals["readonly"] && !quals["fixed"]
			c.Attributes = append(c.Attributes, a)
		case "command":
			p.access()
			cmd := &Command{Name: p.ident(), Doc: doc, Timed: quals["timed"], FabricScoped: quals["fabric"]}
			p.expect("(")
			if p.tok.kind == 'i' {
				cmd.request = p.ident()
			}
			p.expect(")")
			p.expect(":")
			cmd.response = p.ident()
			p.expect("=")
			cmd.ID = uint32(p.number())
			p.expect(";")
			c.Commands = append(c.Commands, cmd)
		case "event":
			p.access()
			e := &Event{Name: p.ident(), Doc: doc}
			for _, pr := range []string{"critical", "info", "debug"} {
				if quals[pr] {
					e.Priority = pr
				}
			}
			p.expect("=")
			e.ID = uint32(p.number())
			e.Fields = p.fields()
			c.Events = append(c.Events, e)
		default:
			p.fail("unexpected %q in cluster %s", kw, c.Name)
		}
	}
	p.next()
	return c
}

// resolve links a cluster's type names to types.
func (m *Model) resolve(c *Cluster) error {
	fields := func(where string, fs []*Field) error {
		for _, f := range fs {
			if f.Type = m.lookup(c, f.typeName); f.Type == nil {
				return fmt.Errorf("cluster %s: unknown type %q of %s", c.Name, f.typeName, where)
			}
		}
		return nil
	}
	for _, t := range c.types {
		if err := fields(t.Name, t.Fields); err != nil {
			return err
		}
	}
	for _, a := range c.Attributes {
		if err := fields(a.Name, []*Field{&a.Field}); err != nil {
			return err
		}
	}
	for _, e := range c.Events {
		if err := fields(e.Name, e.Fields); err != nil {
			return err
		}
	}
	for _, cmd := range c.Commands {
		if cmd.request != "" {
			if cmd.Request = m.lookup(c, cmd.request); cmd.Request == nil {
				return fmt.Errorf("cluster %s: unknown request %q", c.Name, cmd.request)
			}
		}
		if cmd.response != "DefaultSuccess" {
			r := c.types[cmd.response]
			if r == nil || len(r.Items) != 1 {
				return fmt.Errorf("cluster %s: unknown response %q", c.Name, cmd.response)
			}
			cmd.Response, cmd.ResponseID = r, uint32(r.Items[0].Value)
		}
	}
	for _, t := range c.types {
		if t.Kind == KindStruct {
			t.Items = nil
		}
	}
	return nil
}

// lookup resolves a type name: the cluster's types, then top-level ones,
// then primitives.
func (m *Model) lookup(c *Cluster, name string) *Type {
	if c != nil {
		if t := c.types[name]; t != nil {
			return t
		}
	}
	if t := m.types[name]; t != nil {
		return t
	}
	if t := m.prims[name]; t != nil {
		return t
	}
	t := primitive(name)
	if t != nil {
		m.prims[name] = t
	}
	return t
}

var primitives = map[string]Kind{
	"boolean": KindBool, "single": KindFloat, "double": KindDouble,
	"char_string": KindString, "long_char_string": KindString,
	"octet_string": KindBytes, "long_octet_string": KindBytes,
	"ipadr": KindBytes, "ipv4adr": KindBytes, "ipv6adr": KindBytes, "ipv6pre": KindBytes, "hwadr": KindBytes,
	"temperature": KindInt, "power_mw": KindInt, "power_mva": KindInt, "power_mvar": KindInt,
	"amperage_ma": KindInt, "voltage_mv": KindInt, "energy_mwh": KindInt, "energy_mvah": KindInt,
	"energy_mvarh": KindInt, "money": KindInt,
}

// primitive returns the type of a primitive name; unknown names are
// unsigned integers (IDs, counters, times) unless they look signed.
func primitive(name string) *Type {
	kind, ok := primitives[name]
	switch {
	case ok:
	case strings.HasPrefix(name, "int") && strings.HasSuffix(name, "s"):
		kind = KindInt
	case strings.HasPrefix(name, "int"), strings.HasPrefix(name, "enum"), strings.HasPrefix(name, "bitmap"),
		strings.HasSuffix(name, "_id"), strings.HasSuffix(name, "_idx"), strings.HasSuffix(name, "_no"),
		strings.HasPrefix(name, "epoch_"), strings.HasPrefix(name, "systime_"), strings.HasPrefix(name, "posix_"),
		strings.HasPrefix(name, "elapsed_"), strings.HasPrefix(name, "percent"),
		name == "status", name == "utc", name == "data_ver", name == "tod", name == "date", name == "priority":
		kind = KindUint
	default:
		return nil
	}
	return &Type{Name: name, Kind: kind}
}
