package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// pdfDoc builds a PDF document using raw PDF 1.4 format.
type pdfDoc struct {
	objects [][]byte
	pages   []int // object numbers of page objects
}

func (d *pdfDoc) addObj(content string) int {
	d.objects = append(d.objects, []byte(content))
	return len(d.objects) // 1-based object numbering
}

// pdfPage accumulates content stream text for a single page.
type pdfPage struct {
	buf strings.Builder
}

// textAt writes black text at an absolute position using Tm (text matrix).
func (p *pdfPage) textAt(x, y float64, font string, size float64, text string) {
	p.buf.WriteString(fmt.Sprintf("BT 0 0 0 rg %s %.0f Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n",
		font, size, x, y, pdfEscape(text)))
}

// textAtColor writes colored text at an absolute position.
func (p *pdfPage) textAtColor(x, y float64, font string, size float64, r, g, b float64, text string) {
	p.buf.WriteString(fmt.Sprintf("BT %.2f %.2f %.2f rg %s %.0f Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n",
		r, g, b, font, size, x, y, pdfEscape(text)))
}

// lineAt draws a horizontal line.
func (p *pdfPage) lineAt(x1, y, x2 float64, width float64) {
	p.buf.WriteString(fmt.Sprintf("%.1f w %.1f %.1f m %.1f %.1f l S\n", width, x1, y, x2, y))
}

// rectFill draws a filled rectangle.
func (p *pdfPage) rectFill(x, y, w, h float64, r, g, b float64) {
	p.buf.WriteString(fmt.Sprintf("%.2f %.2f %.2f rg %.1f %.1f %.1f %.1f re f\n", r, g, b, x, y, w, h))
}

// content returns the stream content.
func (p *pdfPage) content() string {
	return p.buf.String()
}

const (
	pageW   = 612.0
	pageH   = 792.0
	marginL = 50.0
	marginR = 50.0
	marginT = 60.0
	marginB = 60.0
)

// RenderPDF writes a compliance audit report as a PDF.
func RenderPDF(w io.Writer, report *models.AuditReport) error {
	d := &pdfDoc{}

	// Reserve objects 1-5
	d.addObj("") // 1: catalog
	d.addObj("") // 2: pages
	d.addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	d.addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	d.addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

	contentW := pageW - marginL - marginR
	var allPages []string

	// ==================== Title Page ====================
	tp := &pdfPage{}

	// Header background
	tp.rectFill(0, pageH-160, pageW, 160, 0.12, 0.12, 0.18)

	// Title text (white on dark header)
	tp.textAtColor(marginL, 680, "/F2", 28, 1, 1, 1, "actions-comply")
	tp.textAtColor(marginL, 655, "/F1", 14, 1, 1, 1, "Compliance Audit Report")
	tp.textAtColor(marginL, 638, "/F1", 10, 0.7, 0.7, 0.7, "SOC2 Trust Services Criteria  |  ISO 27001 Annex A")

	// Metadata section
	y := 580.0
	metaLines := []string{
		fmt.Sprintf("Organisation:   %s", report.Org),
		fmt.Sprintf("Repositories:   %s", strings.Join(report.Repos, ", ")),
		fmt.Sprintf("Report ID:      %s", report.ID),
		fmt.Sprintf("Generated:      %s", report.GeneratedAt.Format(time.RFC3339)),
	}
	fws := make([]string, len(report.Frameworks))
	for i, f := range report.Frameworks {
		fws[i] = strings.ToUpper(string(f))
	}
	metaLines = append(metaLines, fmt.Sprintf("Frameworks:     %s", strings.Join(fws, ", ")))

	for _, line := range metaLines {
		tp.textAt(marginL, y, "/F1", 10, line)
		y -= 18
	}

	// Scorecard box
	y -= 20
	tp.rectFill(marginL, y-90, contentW, 100, 0.96, 0.96, 0.96)
	tp.textAt(marginL+10, y, "/F2", 13, "Scorecard")
	y -= 22
	tp.textAt(marginL+10, y, "/F1", 11,
		fmt.Sprintf("Total Findings: %d", report.Summary.TotalFindings))
	y -= 18
	tp.textAt(marginL+10, y, "/F1", 10,
		fmt.Sprintf("Pass: %d    Fail: %d    Warn: %d    Skipped: %d",
			report.Summary.CountByStatus[models.StatusPass],
			report.Summary.CountByStatus[models.StatusFail],
			report.Summary.CountByStatus[models.StatusWarn],
			report.Summary.CountByStatus[models.StatusSkipped]))
	y -= 16
	tp.textAt(marginL+10, y, "/F1", 10,
		fmt.Sprintf("Critical: %d    High: %d    Medium: %d    Low: %d    Info: %d",
			report.Summary.CountBySeverity[models.SeverityCritical],
			report.Summary.CountBySeverity[models.SeverityHigh],
			report.Summary.CountBySeverity[models.SeverityMedium],
			report.Summary.CountBySeverity[models.SeverityLow],
			report.Summary.CountBySeverity[models.SeverityInfo]))

	allPages = append(allPages, tp.content())

	// ==================== Control Status + Check Summary Page ====================
	cp := &pdfPage{}
	y = pageH - marginT

	cp.textAt(marginL, y, "/F2", 16, "Control Status")
	y -= 8
	cp.lineAt(marginL, y, pageW-marginR, 0.5)
	y -= 20

	for ctrl, status := range report.Summary.ControlStatus {
		label := strings.ToUpper(string(status))
		r, g, b := 0.5, 0.5, 0.5
		switch status {
		case models.StatusFail:
			cp.rectFill(marginL, y-3, 4, 12, 0.9, 0.2, 0.2)
			r, g, b = 0.85, 0.15, 0.15
		case models.StatusWarn:
			cp.rectFill(marginL, y-3, 4, 12, 0.95, 0.7, 0.1)
			r, g, b = 0.85, 0.6, 0.0
		case models.StatusPass:
			cp.rectFill(marginL, y-3, 4, 12, 0.2, 0.7, 0.3)
			r, g, b = 0.1, 0.6, 0.2
		}
		cp.textAt(marginL+12, y, "/F1", 10, string(ctrl))
		cp.textAtColor(marginL+220, y, "/F2", 10, r, g, b, label)
		y -= 18
	}

	y -= 25
	cp.textAt(marginL, y, "/F2", 16, "Check Summary")
	y -= 8
	cp.lineAt(marginL, y, pageW-marginR, 0.5)
	y -= 20

	// Table header
	cp.rectFill(marginL, y-3, contentW, 16, 0.92, 0.92, 0.92)
	cp.textAt(marginL+5, y, "/F2", 9, "Check")
	cp.textAt(marginL+290, y, "/F2", 9, "Fail")
	cp.textAt(marginL+340, y, "/F2", 9, "Warn")
	cp.textAt(marginL+390, y, "/F2", 9, "Pass")
	cp.textAt(marginL+440, y, "/F2", 9, "Skip")
	y -= 18

	for _, cr := range report.CheckResults {
		fail, warn, pass, skip := 0, 0, 0, 0
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
		cp.textAt(marginL+5, y, "/F3", 8, truncStr(cr.CheckID, 50))
		cp.textAt(marginL+295, y, "/F1", 9, fmt.Sprintf("%d", fail))
		cp.textAt(marginL+345, y, "/F1", 9, fmt.Sprintf("%d", warn))
		cp.textAt(marginL+395, y, "/F1", 9, fmt.Sprintf("%d", pass))
		cp.textAt(marginL+445, y, "/F1", 9, fmt.Sprintf("%d", skip))
		y -= 16
		cp.lineAt(marginL, y+4, pageW-marginR, 0.2)
	}

	allPages = append(allPages, cp.content())

	// ==================== Finding Pages ====================
	curPage := &pdfPage{}
	y = pageH - marginT

	newPage := func() {
		allPages = append(allPages, curPage.content())
		curPage = &pdfPage{}
		y = pageH - marginT
	}
	checkSpace := func(needed float64) {
		if y < marginB+needed {
			newPage()
		}
	}

	for _, cr := range report.CheckResults {
		groups := groupFindings(cr)
		if len(groups) == 0 {
			continue
		}

		checkSpace(60)

		// Section header with background
		curPage.rectFill(marginL, y-5, contentW, 22, 0.15, 0.15, 0.22)
		curPage.textAtColor(marginL+8, y, "/F2", 11, 1, 1, 1, cr.CheckID)
		y -= 28

		for _, g := range groups {
			checkSpace(55)

			// Severity indicator bar
			switch g.Severity {
			case models.SeverityCritical:
				curPage.rectFill(marginL, y-2, 3, 14, 0.8, 0.0, 0.0)
			case models.SeverityHigh:
				curPage.rectFill(marginL, y-2, 3, 14, 0.95, 0.3, 0.1)
			case models.SeverityMedium:
				curPage.rectFill(marginL, y-2, 3, 14, 0.95, 0.7, 0.1)
			default:
				curPage.rectFill(marginL, y-2, 3, 14, 0.6, 0.6, 0.6)
			}

			// Status tag (color-coded)
			tag := fmt.Sprintf("[%s/%s]", strings.ToUpper(string(g.Status)), strings.ToUpper(string(g.Severity)))
			tr, tg, tb := 0.5, 0.5, 0.5
			switch g.Severity {
			case models.SeverityCritical:
				tr, tg, tb = 0.8, 0.0, 0.0
			case models.SeverityHigh:
				tr, tg, tb = 0.9, 0.25, 0.05
			case models.SeverityMedium:
				tr, tg, tb = 0.85, 0.6, 0.0
			}
			curPage.textAtColor(marginL+8, y, "/F2", 9, tr, tg, tb, tag)

			if g.Count > 1 {
				curPage.textAt(marginL+120, y, "/F1", 8,
					fmt.Sprintf("(%d occurrences)", g.Count))
			}
			y -= 14

			// Message (wrapped)
			for _, line := range wrapText(g.Message, contentW-20, 9) {
				checkSpace(14)
				curPage.textAt(marginL+12, y, "/F1", 9, line)
				y -= 13
			}

			// Targets
			limit := 3
			if len(g.Targets) < limit {
				limit = len(g.Targets)
			}
			for _, t := range g.Targets[:limit] {
				checkSpace(12)
				curPage.textAt(marginL+18, y, "/F3", 7, truncStr(t, 90))
				y -= 11
			}
			if len(g.Targets) > 3 {
				checkSpace(12)
				curPage.textAt(marginL+18, y, "/F1", 7,
					fmt.Sprintf("... and %d more", len(g.Targets)-3))
				y -= 11
			}

			// Detail
			if g.Detail != "" {
				checkSpace(12)
				curPage.rectFill(marginL+15, y-2, contentW-30, 1, 0.85, 0.85, 0.85)
				y -= 6
				for _, line := range wrapText(g.Detail, contentW-40, 8) {
					checkSpace(11)
					curPage.textAt(marginL+18, y, "/F1", 8, line)
					y -= 11
				}
			}

			y -= 10 // spacing between findings
		}
		y -= 8
	}
	// Flush last page
	allPages = append(allPages, curPage.content())

	// ==================== Build PDF Structure ====================
	resources := fmt.Sprintf("<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>")

	for i, content := range allPages {
		streamObj := d.addObj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))

		pageNum := i + 1
		footer := fmt.Sprintf(
			"BT /F1 8 Tf 0.5 0.5 0.5 rg 1 0 0 1 %.1f 35.0 Tm (Page %d of %d) Tj ET\n"+
				"0.85 0.85 0.85 RG 0.5 w %.1f 50.0 m %.1f 50.0 l S",
			pageW/2-25, pageNum, len(allPages), marginL, pageW-marginR)
		footerObj := d.addObj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(footer), footer))

		pageObjNum := d.addObj(fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Contents [%d 0 R %d 0 R] /Resources %s >>",
			pageW, pageH, streamObj, footerObj, resources))
		d.pages = append(d.pages, pageObjNum)
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

func (d *pdfDoc) writePDF(w io.Writer) error {
	var written int64
	write := func(s string) {
		n, _ := fmt.Fprint(w, s)
		written += int64(n)
	}

	write("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	offsets := make([]int64, len(d.objects))
	for i, obj := range d.objects {
		offsets[i] = written
		s := fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, string(obj))
		write(s)
	}

	xrefStart := written
	write(fmt.Sprintf("xref\n0 %d\n", len(d.objects)+1))
	write("0000000000 65535 f \n")
	for _, off := range offsets {
		write(fmt.Sprintf("%010d 00000 n \n", off))
	}

	write(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\n", len(d.objects)+1))
	write(fmt.Sprintf("startxref\n%d\n%%%%EOF\n", xrefStart))

	return nil
}

func pdfEscape(s string) string {
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
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > charsPerLine {
			lines = append(lines, current)
			current = word
		} else {
			current += " " + word
		}
	}
	lines = append(lines, current)
	return lines
}
