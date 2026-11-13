package main

import "tinymatter/tlv"

func main() {
	w := tlv.NewWriter(make([]byte, 0, 64))
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(1), 0xFFFFFFFF)
	w.PutInt(tlv.ContextTag(2), -170000)
	w.PutString(tlv.ContextTag(3), "Hello!")
	w.EndContainer()
	r := tlv.NewReader(w.Bytes())
	r.Next()
	r.EnterContainer()
	r.Next()
	v, _ := r.Uint32()
	r.Next()
	i, _ := r.Int32()
	r.Next()
	s, _ := r.UTF8()
	println("uint32", v, "int32", i, "str", string(s), "ok:", v == 0xFFFFFFFF && i == -170000 && string(s) == "Hello!")
}
