package clusters

import "math"

// Colour conversions for applications that drive a light: from the Color
// Control cluster's hue and saturation, CIE xy or colour temperature to
// linear RGB for an LED.

// HSVToRGB converts Matter hue and saturation (0-254 each) at a level
// (0-254, as Level Control's CurrentLevel) to 8-bit RGB.
func HSVToRGB(hue, sat, level uint8) (r, g, b uint8) {
	h := float64(hue) / 254 * 6
	s := float64(sat) / 254
	v := float64(level) / 254
	i := math.Floor(h)
	f := h - i
	p, q, t := v*(1-s), v*(1-s*f), v*(1-s*(1-f))
	var rf, gf, bf float64
	switch int(i) % 6 {
	case 0:
		rf, gf, bf = v, t, p
	case 1:
		rf, gf, bf = q, v, p
	case 2:
		rf, gf, bf = p, v, t
	case 3:
		rf, gf, bf = p, q, v
	case 4:
		rf, gf, bf = t, p, v
	default:
		rf, gf, bf = v, p, q
	}
	return to8(rf), to8(gf), to8(bf)
}

// XYToRGB converts a Matter CIE 1931 colour (x and y in units of 1/65536)
// at a level (0-254) to 8-bit linear RGB with the sRGB primaries,
// normalised so the brightest channel follows the level.
func XYToRGB(x, y uint16, level uint8) (r, g, b uint8) {
	fx, fy := float64(x)/65536, float64(y)/65536
	if fy <= 0 {
		return 0, 0, 0
	}
	X, Y, Z := fx/fy, 1.0, (1-fx-fy)/fy
	rf := 3.2406*X - 1.5372*Y - 0.4986*Z
	gf := -0.9689*X + 1.8758*Y + 0.0415*Z
	bf := 0.0557*X - 0.2040*Y + 1.0570*Z
	return scaleRGB(rf, gf, bf, level)
}

// MiredsToRGB converts a colour temperature in mireds at a level (0-254)
// to 8-bit RGB, after Tanner Helland's fit of the black-body curve.
func MiredsToRGB(mireds uint16, level uint8) (r, g, b uint8) {
	if mireds == 0 {
		mireds = 1
	}
	t := 1e6 / float64(mireds) / 100 // kelvin / 100
	var rf, gf, bf float64
	if t <= 66 {
		rf = 255
		gf = 99.4708025861*math.Log(t) - 161.1195681661
	} else {
		rf = 329.698727446 * math.Pow(t-60, -0.1332047592)
		gf = 288.1221695283 * math.Pow(t-60, -0.0755148492)
	}
	switch {
	case t >= 66:
		bf = 255
	case t <= 19:
		bf = 0
	default:
		bf = 138.5177312231*math.Log(t-10) - 305.0447927307
	}
	return scaleRGB(rf, gf, bf, level)
}

// scaleRGB clamps negative channels and scales so the brightest channel
// is level/254 of full.
func scaleRGB(r, g, b float64, level uint8) (uint8, uint8, uint8) {
	r, g, b = max(r, 0), max(g, 0), max(b, 0)
	m := max(r, g, b)
	if m == 0 {
		return 0, 0, 0
	}
	k := float64(level) / 254 / m
	return to8(r * k), to8(g * k), to8(b * k)
}

func to8(v float64) uint8 {
	return uint8(math.Round(min(max(v, 0), 1) * 255))
}
