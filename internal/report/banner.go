package report

import (
	"strings"
	"unicode/utf8"
)

// Art is the ASCII banner shown on wide interactive terminals. To change the
// look, edit this string (or replace it with any other art) — nothing else
// needs to change. Pad short rows with trailing spaces so every line measures
// the same width (the test enforces it); trailing spaces are invisible when
// rendered.
const Art = `                       █▄           
 ▄▄                    ██ ▄         
 ██ ▄█▀ ▄█▀█▄ ██ ██ ▄████ ████▄▄▀▀█▄
 ████   ██▄█▀ ██▄██ ██ ██ ██   ▄█▀██
▄██ ▀█▄▄▀█▄▄▄▄▄▀██▀▄█▀███▄█▀  ▄▀█▄██
                ██                    v1.0.0
              ▀▀▀                   
			  `

// BrandColor is Keydra's single accent color (256-color palette): a blue
// that reads as "leak/water" without colliding with the severity palette.
const BrandColor = 57

// ArtWidth is the display width of the widest banner line, in columns. The
// CLI uses it to decide whether the banner fits the terminal.
func ArtWidth() int {
	w := 0
	for _, line := range strings.Split(Art, "\n") {
		if n := utf8.RuneCountInString(line); n > w {
			w = n
		}
	}
	return w
}

// artLines returns the banner lines, all in the brand color when color is
// enabled and untouched otherwise.
func (s Style) artLines() []string {
	lines := strings.Split(Art, "\n")
	if !s.Color {
		return lines
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = s.fg256(BrandColor, line)
	}
	return out
}
