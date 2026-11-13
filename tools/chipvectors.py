#!/usr/bin/env python3
"""Convert a connectedhomeip crypto test-vector header (src/crypto/tests/*.h)
into JSON: a list of objects, one per `static const struct ... NAME = {...}`,
with byte-array fields as hex strings and scalar fields as numbers/strings.

    python3 -I tools/chipvectors.py <header.h> > out.json
"""
import json, re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
src = re.sub(r'//[^\n]*', '', src)

arrays = {}
for name, body in re.findall(r'static\s+const\s+uint8_t\s+(\w+)\s*\[\s*\w*\s*\]\s*=\s*\{(.*?)\}\s*;', src, re.S):
    vals = [v.strip() for v in body.split(',') if v.strip()]
    arrays[name] = bytes(int(v, 0) for v in vals).hex()

out = []
for typ, name, body in re.findall(r'static\s+const\s+struct\s+(\w+)\s+(\w+)\s*=\s*\{(.*?)\}\s*;', src, re.S):
    obj = {'_name': name}
    for field, value in re.findall(r'\.(\w+)\s*=\s*([^,]+)', body):
        value = value.strip()
        if value in ('nullptr', 'NULL'):
            obj[field] = ''
        elif value in arrays:
            obj[field] = arrays[value]
        elif re.fullmatch(r'-?(0x[0-9a-fA-F]+|\d+)', value):
            obj[field] = int(value, 0)
        else:
            obj[field] = value
    out.append(obj)
json.dump(out, sys.stdout, indent=1)
print()
