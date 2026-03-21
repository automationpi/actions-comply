package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"github.com/automationpi/actions-comply/pkg/models"
)

// ── PDF primitives ──────────────────────────────────────────────────────────

type pdfDoc struct {
	objects [][]byte
	pages   []int
}

func (d *pdfDoc) addObj(content string) int {
	d.objects = append(d.objects, []byte(content))
	return len(d.objects)
}

type pdfPage struct{ buf strings.Builder }

func (p *pdfPage) text(x, y float64, font string, size float64, text string) {
	p.buf.WriteString(fmt.Sprintf("BT 0 0 0 rg %s %.0f Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n",
		font, size, x, y, pdfEsc(text)))
}

func (p *pdfPage) textC(x, y float64, font string, size float64, r, g, b float64, text string) {
	p.buf.WriteString(fmt.Sprintf("BT %.2f %.2f %.2f rg %s %.0f Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n",
		r, g, b, font, size, x, y, pdfEsc(text)))
}

func (p *pdfPage) rect(x, y, w, h, r, g, b float64) {
	p.buf.WriteString(fmt.Sprintf("%.2f %.2f %.2f rg %.1f %.1f %.1f %.1f re f\n", r, g, b, x, y, w, h))
}

func (p *pdfPage) rectStroke(x, y, w, h float64, sr, sg, sb float64, lw float64) {
	p.buf.WriteString(fmt.Sprintf("%.2f %.2f %.2f RG %.1f w %.1f %.1f %.1f %.1f re S\n",
		sr, sg, sb, lw, x, y, w, h))
}

func (p *pdfPage) line(x1, y1, x2, y2 float64, r, g, b, w float64) {
	p.buf.WriteString(fmt.Sprintf("%.2f %.2f %.2f RG %.1f w %.1f %.1f m %.1f %.1f l S\n",
		r, g, b, w, x1, y1, x2, y2))
}

func (p *pdfPage) content() string { return p.buf.String() }

const (
	pw = 612.0 // US Letter
	ph = 792.0
	ml = 45.0  // margins
	mr = 45.0
	mt = 45.0
	mb = 55.0
)

var cw = pw - ml - mr // content width

// ── Color palette ───────────────────────────────────────────────────────────

type rgb struct{ r, g, b float64 }

var (
	colDark     = rgb{0.11, 0.11, 0.16}
	colWhite    = rgb{1, 1, 1}
	colGrayBg   = rgb{0.965, 0.965, 0.97}
	colGrayLine = rgb{0.88, 0.88, 0.88}
	colGrayText = rgb{0.45, 0.45, 0.45}
	colRed      = rgb{0.85, 0.18, 0.18}
	colOrange   = rgb{0.90, 0.35, 0.08}
	colAmber    = rgb{0.85, 0.60, 0.0}
	colGreen    = rgb{0.15, 0.62, 0.28}
	colBlue     = rgb{0.18, 0.42, 0.78}

	colCritBg = rgb{0.95, 0.88, 0.88}
	colHighBg = rgb{0.98, 0.93, 0.88}
	colMedBg  = rgb{0.98, 0.96, 0.88}
	colInfoBg = rgb{0.92, 0.95, 0.98}
)

func sevColor(s models.Severity) rgb {
	switch s {
	case models.SeverityCritical:
		return colRed
	case models.SeverityHigh:
		return colOrange
	case models.SeverityMedium:
		return colAmber
	default:
		return colGrayText
	}
}

func sevBg(s models.Severity) rgb {
	switch s {
	case models.SeverityCritical:
		return colCritBg
	case models.SeverityHigh:
		return colHighBg
	case models.SeverityMedium:
		return colMedBg
	default:
		return colInfoBg
	}
}

// ── Main render ─────────────────────────────────────────────────────────────

func RenderPDF(w io.Writer, report *models.AuditReport) error {
	d := &pdfDoc{}
	d.addObj("") // 1: catalog
	d.addObj("") // 2: pages
	d.addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	d.addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	d.addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

	var allPages []string

	// ── Page 1: Cover + Scorecard + Controls + Check Summary ─────────────
	p1 := &pdfPage{}

	// Dark banner
	p1.rect(0, ph-130, pw, 130, colDark.r, colDark.g, colDark.b)
	// Accent line under banner
	p1.rect(0, ph-133, pw, 3, colBlue.r, colBlue.g, colBlue.b)

	p1.textC(ml, ph-55, "/F2", 26, 1, 1, 1, "actions-comply")
	p1.textC(ml, ph-78, "/F1", 12, 0.75, 0.75, 0.8, "Compliance Audit Report")
	// Right-aligned date
	p1.textC(pw-mr-160, ph-55, "/F1", 9, 0.6, 0.6, 0.65,
		report.GeneratedAt.Format("2 January 2006"))
	p1.textC(pw-mr-160, ph-70, "/F1", 8, 0.6, 0.6, 0.65,
		fmt.Sprintf("Report %s", report.ID))

	y := ph - 155.0

	// Metadata row
	fws := make([]string, len(report.Frameworks))
	for i, f := range report.Frameworks {
		fws[i] = strings.ToUpper(string(f))
	}
	metaItems := []struct{ k, v string }{
		{"Org", report.Org},
		{"Repos", strings.Join(report.Repos, ", ")},
		{"Frameworks", strings.Join(fws, ", ")},
		{"Period", fmt.Sprintf("%s to %s",
			report.Period.From.Format("2006-01-02"),
			report.Period.To.Format("2006-01-02"))},
	}
	p1.rect(ml, y-20, cw, 22, colGrayBg.r, colGrayBg.g, colGrayBg.b)
	mx := ml + 8.0
	for _, m := range metaItems {
		p1.textC(mx, y-14, "/F2", 7, colGrayText.r, colGrayText.g, colGrayText.b, m.k+":")
		p1.text(mx+textWidth(m.k+":")+4, y-14, "/F1", 7, m.v)
		mx += textWidth(m.k+": "+m.v) + 20
		if mx > pw-mr-50 {
			break
		}
	}
	y -= 35

	// ── Scorecard metric cards ──
	p1.text(ml, y, "/F2", 13, "Scorecard")
	y -= 18

	cardW := (cw - 20) / 5.0 // 5 cards
	cardH := 52.0
	cards := []struct {
		label string
		value int
		col   rgb
	}{
		{"TOTAL", report.Summary.TotalFindings, colDark},
		{"PASS", report.Summary.CountByStatus[models.StatusPass], colGreen},
		{"FAIL", report.Summary.CountByStatus[models.StatusFail], colRed},
		{"WARN", report.Summary.CountByStatus[models.StatusWarn], colAmber},
		{"CRITICAL", report.Summary.CountBySeverity[models.SeverityCritical], colRed},
	}
	for i, c := range cards {
		cx := ml + float64(i)*(cardW+5)
		p1.rect(cx, y-cardH, cardW, cardH, colGrayBg.r, colGrayBg.g, colGrayBg.b)
		// Left accent bar
		p1.rect(cx, y-cardH, 3, cardH, c.col.r, c.col.g, c.col.b)
		p1.textC(cx+14, y-20, "/F2", 22, c.col.r, c.col.g, c.col.b,
			fmt.Sprintf("%d", c.value))
		p1.textC(cx+14, y-38, "/F1", 7, colGrayText.r, colGrayText.g, colGrayText.b, c.label)
	}
	y -= cardH + 8

	// Second row: severity breakdown
	smallCards := []struct {
		label string
		value int
		col   rgb
	}{
		{"HIGH", report.Summary.CountBySeverity[models.SeverityHigh], colOrange},
		{"MEDIUM", report.Summary.CountBySeverity[models.SeverityMedium], colAmber},
		{"LOW", report.Summary.CountBySeverity[models.SeverityLow], colGrayText},
		{"INFO", report.Summary.CountBySeverity[models.SeverityInfo], colBlue},
		{"SKIPPED", report.Summary.CountByStatus[models.StatusSkipped], colGrayText},
	}
	scH := 32.0
	for i, c := range smallCards {
		cx := ml + float64(i)*(cardW+5)
		p1.rect(cx, y-scH, cardW, scH, colGrayBg.r, colGrayBg.g, colGrayBg.b)
		p1.rect(cx, y-scH, 3, scH, c.col.r, c.col.g, c.col.b)
		p1.textC(cx+14, y-14, "/F2", 14, c.col.r, c.col.g, c.col.b,
			fmt.Sprintf("%d", c.value))
		p1.textC(cx+14, y-26, "/F1", 6, colGrayText.r, colGrayText.g, colGrayText.b, c.label)
	}
	y -= scH + 20

	// ── Control Status (two columns) ──
	p1.text(ml, y, "/F2", 12, "Control Status")
	y -= 5
	p1.line(ml, y, pw-mr, y, colGrayLine.r, colGrayLine.g, colGrayLine.b, 0.5)
	y -= 14

	// Sort controls for consistent output
	var ctrls []models.ControlID
	for c := range report.Summary.ControlStatus {
		ctrls = append(ctrls, c)
	}
	sort.Slice(ctrls, func(i, j int) bool { return string(ctrls[i]) < string(ctrls[j]) })

	colWidth := cw / 2
	col := 0
	rowY := y
	for i, ctrl := range ctrls {
		status := report.Summary.ControlStatus[ctrl]
		cx := ml + float64(col)*colWidth
		sc := sevColorForStatus(status)
		// Status dot
		p1.rect(cx+2, rowY-1, 6, 6, sc.r, sc.g, sc.b)
		p1.text(cx+14, rowY, "/F1", 8, string(ctrl))
		p1.textC(cx+colWidth-45, rowY, "/F2", 8, sc.r, sc.g, sc.b,
			strings.ToUpper(string(status)))
		col++
		if col >= 2 {
			col = 0
			rowY -= 14
		}
		_ = i
	}
	if col != 0 {
		rowY -= 14
	}
	y = rowY - 12

	// ── Check Summary Table ──
	p1.text(ml, y, "/F2", 12, "Check Summary")
	y -= 5
	p1.line(ml, y, pw-mr, y, colGrayLine.r, colGrayLine.g, colGrayLine.b, 0.5)
	y -= 16

	// Header
	p1.rect(ml, y-2, cw, 14, colDark.r, colDark.g, colDark.b)
	p1.textC(ml+8, y+1, "/F2", 8, 1, 1, 1, "CHECK")
	colPositions := []float64{ml + 310, ml + 360, ml + 410, ml + 460}
	headers := []string{"FAIL", "WARN", "PASS", "SKIP"}
	for i, h := range headers {
		p1.textC(colPositions[i], y+1, "/F2", 8, 1, 1, 1, h)
	}
	y -= 16

	for i, cr := range report.CheckResults {
		fail, warn, pass, skip := countStatuses(cr)
		if i%2 == 0 {
			p1.rect(ml, y-2, cw, 14, colGrayBg.r, colGrayBg.g, colGrayBg.b)
		}
		p1.text(ml+8, y+1, "/F3", 7, truncStr(cr.CheckID, 55))
		nums := []int{fail, warn, pass, skip}
		numCols := []rgb{colRed, colAmber, colGreen, colGrayText}
		for j, n := range nums {
			if n > 0 {
				p1.textC(colPositions[j], y+1, "/F2", 8, numCols[j].r, numCols[j].g, numCols[j].b,
					fmt.Sprintf("%d", n))
			} else {
				p1.textC(colPositions[j], y+1, "/F1", 8, 0.78, 0.78, 0.78, "0")
			}
		}
		y -= 14
	}

	allPages = append(allPages, p1.content())

	// ── Page 2: Executive Summary + What This Means ──────────────────────
	p2 := &pdfPage{}
	y = ph - mt

	p2.text(ml, y, "/F2", 16, "Executive Summary")
	y -= 6
	p2.line(ml, y, pw-mr, y, colGrayLine.r, colGrayLine.g, colGrayLine.b, 0.5)
	y -= 16

	// Build fail counts per check
	failsByCheck := make(map[string]int)
	totalFails := 0
	for _, cr := range report.CheckResults {
		f, _, _, _ := countStatuses(cr)
		if f > 0 {
			failsByCheck[cr.CheckID] = f
			totalFails += f
		}
	}

	summaryLines := executiveSummary(
		report.Summary.TotalFindings, totalFails,
		report.Summary.CountBySeverity[models.SeverityCritical],
		failsByCheck)

	for _, ln := range summaryLines {
		if ln == "" {
			y -= 6
			continue
		}
		p2.text(ml+5, y, "/F1", 9, ln)
		y -= 13
	}

	y -= 20

	// ── What These Checks Mean ──
	p2.text(ml, y, "/F2", 14, "What These Checks Mean")
	y -= 6
	p2.line(ml, y, pw-mr, y, colGrayLine.r, colGrayLine.g, colGrayLine.b, 0.5)
	y -= 14

	p2.textC(ml+5, y, "/F1", 8, colGrayText.r, colGrayText.g, colGrayText.b,
		"Each check maps to specific SOC2 and ISO 27001 controls. Here is what they look for and why.")
	y -= 16

	// Sorted check IDs for consistent ordering
	checkOrder := []string{
		"permissions.workflow_overage",
		"supplychain.unpinned_actions",
		"securedev.scan_coverage",
		"changetrail.deploy_approval",
		"supplychain.action_bom",
	}

	for _, checkID := range checkOrder {
		exp, ok := checkExplainers[checkID]
		if !ok {
			continue
		}

		// Check if we need a new page
		if y < mb+110 {
			allPages = append(allPages, p2.content())
			p2 = &pdfPage{}
			y = ph - mt
		}

		// Check title with accent
		sc := colBlue
		if f, ok := failsByCheck[checkID]; ok && f > 0 {
			sc = colOrange
		}
		p2.rect(ml, y-2, 3, 12, sc.r, sc.g, sc.b)
		p2.text(ml+10, y, "/F2", 10, exp.Title)
		p2.textC(ml+10, y-12, "/F3", 7, colGrayText.r, colGrayText.g, colGrayText.b, checkID)
		y -= 26

		// Why it matters
		p2.textC(ml+10, y, "/F2", 8, colGrayText.r, colGrayText.g, colGrayText.b, "WHY IT MATTERS")
		y -= 11
		for _, ln := range wrapText(exp.Why, cw-25, 8) {
			p2.text(ml+10, y, "/F1", 8, ln)
			y -= 10
		}
		y -= 4

		// Risk
		p2.textC(ml+10, y, "/F2", 8, colRed.r, colRed.g, colRed.b, "RISK")
		y -= 11
		for _, ln := range wrapText(exp.Risk, cw-25, 8) {
			p2.text(ml+10, y, "/F1", 8, ln)
			y -= 10
		}
		y -= 4

		// How to fix
		p2.textC(ml+10, y, "/F2", 8, colGreen.r, colGreen.g, colGreen.b, "HOW TO FIX")
		y -= 11
		for _, ln := range wrapText(exp.FixHint, cw-25, 8) {
			p2.text(ml+10, y, "/F1", 8, ln)
			y -= 10
		}

		// Controls
		p2.textC(ml+10, y-2, "/F1", 7, colGrayText.r, colGrayText.g, colGrayText.b, exp.Controls)
		y -= 14

		// Separator
		p2.line(ml+10, y, pw-mr-10, y, 0.92, 0.92, 0.92, 0.3)
		y -= 12
	}

	allPages = append(allPages, p2.content())

	// ── Finding Pages ────────────────────────────────────────────────────
	cur := &pdfPage{}
	y = ph - mt

	flush := func() {
		allPages = append(allPages, cur.content())
		cur = &pdfPage{}
		y = ph - mt
	}
	need := func(n float64) {
		if y < mb+n {
			flush()
		}
	}

	for _, cr := range report.CheckResults {
		groups := groupFindings(cr)
		if len(groups) == 0 {
			continue
		}

		// Section header space: banner + optional context line
		headerSpace := 30.0
		if exp, ok := checkExplainers[cr.CheckID]; ok {
			_ = exp
			headerSpace = 46.0
		}
		need(headerSpace + 50)

		// Section banner
		cur.rect(ml, y-4, cw, 20, colDark.r, colDark.g, colDark.b)
		cur.rect(ml, y-4, 4, 20, colBlue.r, colBlue.g, colBlue.b) // accent
		cur.textC(ml+12, y, "/F2", 10, 1, 1, 1, cr.CheckID)

		// Pass count on right
		failN, _, passN, _ := countStatuses(cr)
		if passN > 0 {
			cur.textC(pw-mr-60, y, "/F1", 8, 0.6, 0.6, 0.65,
				fmt.Sprintf("%d passed", passN))
		}
		y -= 24

		// Brief context line under section header
		if exp, ok := checkExplainers[cr.CheckID]; ok {
			hint := exp.FixHint
			if failN == 0 {
				hint = "All checks passed for this category."
			}
			for _, ln := range wrapText(hint, cw-20, 7.5) {
				cur.textC(ml+8, y, "/F1", 7.5, colGrayText.r, colGrayText.g, colGrayText.b, ln)
				y -= 10
			}
			y -= 4
		}

		for _, g := range groups {
			need(50)

			sc := sevColor(g.Severity)
			bg := sevBg(g.Severity)

			// Finding card background
			cardH := estimateCardHeight(g)
			cur.rect(ml+4, y-cardH+12, cw-8, cardH, bg.r, bg.g, bg.b)
			// Left severity bar
			cur.rect(ml+4, y-cardH+12, 3, cardH, sc.r, sc.g, sc.b)

			// Tag + count
			tag := fmt.Sprintf("%s / %s",
				strings.ToUpper(string(g.Status)),
				strings.ToUpper(string(g.Severity)))
			cur.textC(ml+14, y, "/F2", 8, sc.r, sc.g, sc.b, tag)
			if g.Count > 1 {
				cur.textC(ml+130, y, "/F1", 8, colGrayText.r, colGrayText.g, colGrayText.b,
					fmt.Sprintf("%d occurrences", g.Count))
			}
			y -= 13

			// Message
			for _, ln := range wrapText(g.Message, cw-40, 9) {
				need(12)
				cur.text(ml+14, y, "/F2", 9, ln)
				y -= 12
			}

			// Targets
			limit := 3
			if len(g.Targets) < limit {
				limit = len(g.Targets)
			}
			for _, t := range g.Targets[:limit] {
				need(10)
				cur.textC(ml+18, y, "/F3", 6.5, colGrayText.r, colGrayText.g, colGrayText.b,
					truncStr(t, 100))
				y -= 9
			}
			if len(g.Targets) > 3 {
				need(10)
				cur.textC(ml+18, y, "/F1", 6.5, colGrayText.r, colGrayText.g, colGrayText.b,
					fmt.Sprintf("+ %d more", len(g.Targets)-3))
				y -= 9
			}

			// Remediation (compact, muted)
			if g.Detail != "" {
				y -= 3
				for _, ln := range wrapText(g.Detail, cw-50, 7) {
					need(9)
					cur.textC(ml+18, y, "/F1", 7,
						colGrayText.r, colGrayText.g, colGrayText.b, ln)
					y -= 9
				}
			}

			y -= 8
		}
		y -= 6
	}
	allPages = append(allPages, cur.content())

	// ── Assemble PDF ─────────────────────────────────────────────────────
	res := "<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>"

	for i, content := range allPages {
		sObj := d.addObj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))

		pn := i + 1
		ftr := fmt.Sprintf(
			"BT 0.6 0.6 0.6 rg /F1 7 Tf 1 0 0 1 %.1f 28.0 Tm (Page %d of %d) Tj ET\n"+
				"BT 0.6 0.6 0.6 rg /F1 7 Tf 1 0 0 1 %.1f 28.0 Tm (actions-comply) Tj ET\n"+
				"0.88 0.88 0.88 RG 0.4 w %.1f 42.0 m %.1f 42.0 l S",
			pw/2-20, pn, len(allPages), ml, ml, pw-mr)
		fObj := d.addObj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(ftr), ftr))

		pgObj := d.addObj(fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Contents [%d 0 R %d 0 R] /Resources %s >>",
			pw, ph, sObj, fObj, res))
		d.pages = append(d.pages, pgObj)
	}

	d.objects[0] = []byte("<< /Type /Catalog /Pages 2 0 R >>")
	kids := make([]string, len(d.pages))
	for i, p := range d.pages {
		kids[i] = fmt.Sprintf("%d 0 R", p)
	}
	d.objects[1] = []byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kids, " "), len(d.pages)))

	return d.writePDF(w)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func countStatuses(cr models.CheckResult) (fail, warn, pass, skip int) {
	for _, f := range cr.Findings {
		switch f.Status {
		case models.StatusFail:
			fail++
		case models.StatusWarn:
			warn++
		case models.StatusPass:
			pass++
		case models.StatusSkipped:
			skip++
		}
	}
	return
}

func sevColorForStatus(s models.Status) rgb {
	switch s {
	case models.StatusFail:
		return colRed
	case models.StatusWarn:
		return colAmber
	case models.StatusPass:
		return colGreen
	default:
		return colGrayText
	}
}

func estimateCardHeight(g findingGroup) float64 {
	h := 13.0 // tag line
	h += float64(len(wrapText(g.Message, cw-40, 9))) * 12.0
	targets := len(g.Targets)
	if targets > 3 {
		targets = 4
	}
	h += float64(targets) * 9.0
	if g.Detail != "" {
		h += 3 + float64(len(wrapText(g.Detail, cw-50, 7)))*9.0
	}
	h += 4
	return h
}

// textWidth gives a rough width estimate for Helvetica at size ~7-8pt.
func textWidth(s string) float64 {
	return float64(len(s)) * 4.0
}

func (d *pdfDoc) writePDF(w io.Writer) error {
	var written int64
	wr := func(s string) {
		n, _ := fmt.Fprint(w, s)
		written += int64(n)
	}

	wr("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	offsets := make([]int64, len(d.objects))
	for i, obj := range d.objects {
		offsets[i] = written
		s := fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, string(obj))
		wr(s)
	}

	xref := written
	wr(fmt.Sprintf("xref\n0 %d\n", len(d.objects)+1))
	wr("0000000000 65535 f \n")
	for _, off := range offsets {
		wr(fmt.Sprintf("%010d 00000 n \n", off))
	}

	wr(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\n", len(d.objects)+1))
	wr(fmt.Sprintf("startxref\n%d\n%%%%EOF\n", xref))
	return nil
}

func pdfEsc(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func wrapText(text string, width float64, fontSize float64) []string {
	charsPerLine := int(width / (fontSize * 0.5))
	if charsPerLine < 20 {
		charsPerLine = 20
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > charsPerLine {
			lines = append(lines, cur)
			cur = w
		} else {
			cur += " " + w
		}
	}
	return append(lines, cur)
}
