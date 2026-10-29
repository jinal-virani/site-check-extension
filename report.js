// Builds the PDF report with jsPDF + jspdf-autotable (bundled in /vendor, loaded by app.html).
const SAFE = { '–': '-', '—': '-', '‘': "'", '’': "'", '“': '"', '”': '"', '…': '...', '•': '-', '·': '|', '→': '->', '×': 'x', '✓': 'v' };
export const pdfSafe = (s) => String(s ?? '').replace(/[–—‘’“”…•·→×✓]/g, (c) => SAFE[c]).replace(/[^\x20-\x7E\xA0-\xFF\n]/g, '');
const soft = (s, n = 46) => pdfSafe(s).replace(new RegExp(`[^\\s]{${n},}`, 'g'), (t) => t.match(new RegExp(`.{1,${n}}`, 'g')).join(' '));
const txt = (v) => (v == null || v === '' ? '-' : soft(typeof v === 'object' ? v.t : v));

const TONE = { good: [26, 138, 82], warn: [194, 120, 0], bad: [200, 40, 40], error: [200, 40, 40], info: [40, 100, 200], none: [110, 110, 110] };
const LABEL = { good: 'PASS', warn: 'WARN', bad: 'FAIL', error: 'ERROR', info: 'INFO', none: 'NOT RUN' };
const MAX_ROWS = 300;

export function buildPdf({ jspdf, target, when, items }) {
  const doc = new jspdf.jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });
  const PW = doc.internal.pageSize.getWidth(), PH = doc.internal.pageSize.getHeight(), M = 36, CW = PW - 2 * M, BOTTOM = PH - 44;
  let y = M;
  const table = (opts) => {
    const o = { margin: { left: M, right: M, bottom: 44 }, theme: 'grid', styles: { fontSize: 8, cellPadding: 3, overflow: 'linebreak', lineColor: [215, 217, 222], lineWidth: 0.4, textColor: [30, 30, 34] }, headStyles: { fillColor: [38, 40, 46], textColor: 255, fontStyle: 'bold' }, alternateRowStyles: { fillColor: [247, 248, 250] }, startY: y, ...opts };
    if (typeof doc.autoTable === 'function') doc.autoTable(o); else jspdf.autoTable(doc, o);
    y = doc.lastAutoTable.finalY + 10;
  };
  const ensure = (h) => { if (y + h > BOTTOM) { doc.addPage(); y = M; } };
  const paragraph = (text, { size = 9, style = 'normal', color = [30, 30, 34], font = 'helvetica' } = {}) => {
    doc.setFont(font, style); doc.setFontSize(size); doc.setTextColor(...color);
    for (const line of doc.splitTextToSize(soft(text), CW)) { ensure(size + 4); doc.text(line, M, y + size); y += size + 3; }
    y += 4;
  };

  // ---- cover + overview ----
  const counts = {}; items.forEach((i) => { const t = i.result?.tone || 'none'; counts[t] = (counts[t] || 0) + 1; });
  doc.setFont('helvetica', 'bold'); doc.setFontSize(22); doc.setTextColor(20, 20, 24); doc.text('Site Check Report', M, y + 20); y += 34;
  doc.setFont('helvetica', 'normal'); doc.setFontSize(11); doc.setTextColor(60, 60, 66);
  doc.text(pdfSafe(target), M, y + 10); y += 18;
  doc.setFontSize(9); doc.setTextColor(110, 110, 116);
  doc.text(`Generated ${when}  |  ${items.length} checks  |  ${['good', 'warn', 'bad', 'error', 'info'].filter((t) => counts[t]).map((t) => `${counts[t]} ${LABEL[t].toLowerCase()}`).join(', ')}`, M, y + 8); y += 22;

  table({
    head: [['#', 'Group', 'Check', 'Status', 'Result']],
    body: items.map((it, i) => [i + 1, it.group, it.title, LABEL[it.result?.tone || 'none'], txt(it.result?.summary || 'This check was not run.')]),
    columnStyles: { 0: { cellWidth: 26 }, 1: { cellWidth: 110 }, 2: { cellWidth: 140 }, 3: { cellWidth: 52, fontStyle: 'bold' } },
    didParseCell: (d) => { if (d.section === 'body' && d.column.index === 3) { const k = Object.keys(LABEL).find((t) => LABEL[t] === d.cell.raw); d.cell.styles.textColor = TONE[k]; } },
  });

  // ---- one block per check ----
  items.forEach((it, idx) => {
    const r = it.result, tone = r?.tone || 'none';
    if (idx === 0) { doc.addPage(); y = M; } else { ensure(150); y += 14; }
    doc.setFillColor(30, 32, 36); doc.rect(M, y, CW, 24, 'F');
    doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(255, 255, 255); doc.text(`${idx + 1}. ${pdfSafe(it.title)}`, M + 10, y + 16);
    doc.setTextColor(...(tone === 'good' ? [110, 220, 160] : tone === 'warn' ? [250, 195, 80] : tone === 'info' ? [140, 180, 255] : tone === 'none' ? [190, 190, 190] : [255, 130, 130]));
    doc.text(LABEL[tone], PW - M - 10, y + 16, { align: 'right' }); y += 32;
    paragraph(`${it.group}  |  ${it.desc}`, { size: 8, style: 'italic', color: [110, 110, 116] });
    paragraph(r?.summary || 'This check was not run.', { size: 10.5, style: 'bold' });
    for (const s of r?.sections || []) {
      if (!s) continue;
      if (s.title) { ensure(40); paragraph(s.title, { size: 9.5, style: 'bold', color: [60, 60, 66] }); y -= 2; }
      if (s.kv) table({ body: s.kv.map(([k, v]) => [k, txt(v)]), columnStyles: { 0: { cellWidth: 170, fontStyle: 'bold', fillColor: [240, 241, 244] } } });
      if (s.table) {
        const rows = s.table.rows.slice(0, MAX_ROWS).map((row) => row.map(txt));
        if (s.table.rows.length > MAX_ROWS) rows.push([`... ${s.table.rows.length - MAX_ROWS} more rows not shown`, ...Array(s.table.head.length - 1).fill('')]);
        table({ head: [s.table.head.map(pdfSafe)], body: rows });
      }
      if (s.list?.length) {
        const rows = s.list.slice(0, MAX_ROWS).map((v) => [txt(v)]);
        if (s.list.length > MAX_ROWS) rows.push([`... ${s.list.length - MAX_ROWS} more not shown`]);
        table({ body: rows });
      }
      if (s.text) paragraph(s.text);
      if (s.pre) table({ body: [[soft(s.pre.slice(0, 3500), 110)]], styles: { font: 'courier', fontSize: 7, cellPadding: 4, lineColor: [215, 217, 222], lineWidth: 0.4, textColor: [30, 30, 34] } });
      if (s.img) paragraph('(Image not included in the PDF. Open the dashboard to see it.)', { size: 8, style: 'italic', color: [110, 110, 116] });
      if (s.note) paragraph(s.note, { size: 8, style: 'italic', color: [110, 110, 116] });
    }
  });

  // ---- footers ----
  const n = doc.getNumberOfPages();
  for (let p = 1; p <= n; p++) {
    doc.setPage(p); doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(130, 130, 136);
    doc.text(`Site Check Panel  |  ${pdfSafe(target)}`, M, PH - 22);
    doc.text(`Page ${p} of ${n}`, PW - M, PH - 22, { align: 'right' });
  }
  return doc;
}
