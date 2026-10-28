#!/usr/bin/env python3
"""
Tests for structured-document extraction in the read_file tool.

Covers PDF extraction and .ipynb / .docx / .xlsx extraction (ported from Kilo-Org/kilocode
#10733, #10737, #10740) and the read_file_tool integration: pagination,
line-numbering, graceful fallback on malformed input, and hidden-sheet
omission.

Run with:  scripts/run_tests.sh tests/tools/test_read_extract.py -v
"""

import json
import os
import tempfile
import unittest
import zipfile

import pytest
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from tools.read_extract import (
    ExtractionError,
    extract_document_text,
    is_extractable_document,
)
from tools.file_tools import read_file_tool


# ---------------------------------------------------------------------------
# Fixture builders — construct minimal valid OOXML / notebook files.
# ---------------------------------------------------------------------------

def _write_notebook(path, cells, nbformat=4):
    nb = {"cells": cells, "metadata": {}, "nbformat": nbformat, "nbformat_minor": 5}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(nb, fh)


def _write_docx(path, document_xml):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", document_xml)


def _write_pdf(path, pages=(), *, image_only=False, password=None, owner_password=None):
    """Generate a small PDF with compressed text streams or an inline image."""
    writer = PdfWriter()
    font = DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    })
    for lines in ([[]] if image_only else pages):
        page = writer.add_blank_page(width=300, height=300)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
        })
        stream = DecodedStreamObject()
        if image_only:
            # A real one-pixel RGB image, with no text layer.
            content = b"q 100 0 0 100 0 0 cm BI /W 1 /H 1 /CS /RGB /BPC 8 ID \xff\x00\x00 EI Q"
        else:
            commands = ["BT /F1 12 Tf 14 TL 20 280 Td"]
            for line in lines:
                escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                commands.append(f"({escaped}) Tj T*")
            commands.append("ET")
            content = "\n".join(commands).encode("latin-1")
        stream.set_data(content)
        page[NameObject("/Contents")] = stream.flate_encode()
    if password is not None:
        writer.encrypt(password, owner_password=owner_password)
    writer.write(path)


def _write_xlsx(path, *, workbook, rels, shared, sheets):
    """sheets: dict of part-name -> xml string."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        if shared is not None:
            z.writestr("xl/sharedStrings.xml", shared)
        for part, xml in sheets.items():
            z.writestr(part, xml)


_NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_NS_S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


# ---------------------------------------------------------------------------
# is_extractable_document
# ---------------------------------------------------------------------------

class TestIsExtractable(unittest.TestCase):
    def test_recognized_extensions(self):
        self.assertTrue(is_extractable_document("a.ipynb"))
        self.assertTrue(is_extractable_document("/x/B.DOCX"))
        self.assertTrue(is_extractable_document("report.xlsx"))
        self.assertTrue(is_extractable_document("report.PDF"))

    def test_unrecognized_extensions(self):
        self.assertFalse(is_extractable_document("a.py"))
        self.assertFalse(is_extractable_document("a.png"))
        self.assertFalse(is_extractable_document("a.txt"))


# ---------------------------------------------------------------------------
# Notebooks (.ipynb) — #10733
# ---------------------------------------------------------------------------

class TestNotebookExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rex_nb_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_markdown_and_code_in_order(self):
        p = os.path.join(self.tmp, "nb.ipynb")
        _write_notebook(p, [
            {"cell_type": "markdown", "source": ["# Title\n", "para"]},
            {"cell_type": "code", "source": "x = 1\nprint(x)",
             "outputs": [{"output_type": "stream", "text": ["1\n"]}],
             "execution_count": 1},
        ])
        text = extract_document_text(p)
        self.assertIn("# Title", text)
        self.assertIn("print(x)", text)
        # Output payloads must NOT leak into the extracted text.
        self.assertNotIn("output_type", text)
        self.assertNotIn("execution_count", text)
        # Order preserved: markdown before code.
        self.assertLess(text.index("Title"), text.index("print(x)"))

    def test_string_source_form(self):
        p = os.path.join(self.tmp, "nb2.ipynb")
        _write_notebook(p, [{"cell_type": "code", "source": "single string source"}])
        self.assertIn("single string source", extract_document_text(p))

    def test_legacy_worksheets_form(self):
        p = os.path.join(self.tmp, "nb3.ipynb")
        nb = {"worksheets": [{"cells": [
            {"cell_type": "code", "input": "ignored", "source": "legacy cell"}]}],
            "nbformat": 3}
        with open(p, "w") as fh:
            json.dump(nb, fh)
        self.assertIn("legacy cell", extract_document_text(p))

    def test_malformed_notebook_raises(self):
        p = os.path.join(self.tmp, "bad.ipynb")
        with open(p, "w") as fh:
            fh.write("{ not valid json")
        with self.assertRaises(ExtractionError):
            extract_document_text(p)

    def test_empty_cells_raises(self):
        p = os.path.join(self.tmp, "empty.ipynb")
        _write_notebook(p, [])
        with self.assertRaises(ExtractionError):
            extract_document_text(p)


# ---------------------------------------------------------------------------
# Word documents (.docx) — #10737
# ---------------------------------------------------------------------------

class TestDocxExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rex_docx_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _doc(self, body):
        return (f'<?xml version="1.0"?><w:document xmlns:w="{_NS_W}">'
                f'<w:body>{body}</w:body></w:document>')

    def test_paragraphs_and_runs(self):
        p = os.path.join(self.tmp, "d.docx")
        _write_docx(p, self._doc(
            '<w:p><w:r><w:t>Hello </w:t></w:r><w:r><w:t>World</w:t></w:r></w:p>'
            '<w:p><w:r><w:t>Second</w:t></w:r></w:p>'))
        text = extract_document_text(p)
        self.assertIn("Hello World", text)
        self.assertIn("Second", text)

    def test_tabs_and_breaks(self):
        p = os.path.join(self.tmp, "d2.docx")
        _write_docx(p, self._doc(
            '<w:p><w:r><w:t>A</w:t><w:tab/><w:t>B</w:t><w:br/><w:t>C</w:t></w:r></w:p>'))
        text = extract_document_text(p)
        self.assertIn("A\tB", text)
        self.assertIn("C", text)

    def test_not_a_zip_raises(self):
        p = os.path.join(self.tmp, "bad.docx")
        with open(p, "wb") as fh:
            fh.write(b"plain bytes, not a zip")
        with self.assertRaises(ExtractionError):
            extract_document_text(p)

    def test_missing_document_xml_raises(self):
        p = os.path.join(self.tmp, "nodoc.docx")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("other.xml", "<x/>")
        with self.assertRaises(ExtractionError):
            extract_document_text(p)


# ---------------------------------------------------------------------------
# Excel workbooks (.xlsx) — #10740
# ---------------------------------------------------------------------------

class TestXlsxExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rex_xlsx_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build(self, path, *, include_hidden=True):
        r = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        hidden_sheet = (f'<sheet name="Hidden" sheetId="2" state="hidden" '
                        f'xmlns:r="{r}" r:id="rId2"/>') if include_hidden else ""
        workbook = (
            f'<workbook xmlns="{_NS_S}" xmlns:r="{r}"><sheets>'
            f'<sheet name="Data" sheetId="1" r:id="rId1"/>{hidden_sheet}'
            f'</sheets></workbook>')
        rels = (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Target="worksheets/sheet1.xml" Type="x"/>'
            '<Relationship Id="rId2" Target="worksheets/sheet2.xml" Type="x"/>'
            '</Relationships>')
        shared = (f'<sst xmlns="{_NS_S}"><si><t>Name</t></si><si><t>Score</t></si>'
                  f'<si><t>Alice</t></si></sst>')
        sheet1 = (
            f'<worksheet xmlns="{_NS_S}"><sheetData>'
            '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
            '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2"><v>95</v></c></row>'
            '</sheetData></worksheet>')
        sheet2 = (f'<worksheet xmlns="{_NS_S}"><sheetData>'
                  '<row r="1"><c r="A1" t="str"><v>SECRETDATA</v></c></row>'
                  '</sheetData></worksheet>')
        _write_xlsx(path, workbook=workbook, rels=rels, shared=shared,
                    sheets={"xl/worksheets/sheet1.xml": sheet1,
                            "xl/worksheets/sheet2.xml": sheet2})

    def test_visible_sheet_content(self):
        p = os.path.join(self.tmp, "wb.xlsx")
        self._build(p)
        text = extract_document_text(p)
        self.assertIn("Data", text)        # sheet label
        self.assertIn("Name\tScore", text)  # shared-string header row
        self.assertIn("Alice\t95", text)    # string + numeric cells

    def test_hidden_sheet_omitted(self):
        p = os.path.join(self.tmp, "wb2.xlsx")
        self._build(p)
        text = extract_document_text(p)
        self.assertNotIn("SECRETDATA", text)
        self.assertNotIn("Hidden", text)

    def test_not_a_zip_raises(self):
        p = os.path.join(self.tmp, "bad.xlsx")
        with open(p, "wb") as fh:
            fh.write(b"nope")
        with self.assertRaises(ExtractionError):
            extract_document_text(p)


# ---------------------------------------------------------------------------
# read_file_tool integration
# ---------------------------------------------------------------------------

class TestReadFileToolIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rex_int_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_notebook_read_is_line_numbered(self):
        p = os.path.join(self.tmp, "nb.ipynb")
        _write_notebook(p, [
            {"cell_type": "markdown", "source": "# H"},
            {"cell_type": "code", "source": "print(1)"},
        ])
        res = json.loads(read_file_tool(p))
        self.assertTrue(res.get("extracted_document"))
        self.assertIn("1|", res["content"])  # line-number gutter
        self.assertIn("print(1)", res["content"])

    def test_pagination(self):
        p = os.path.join(self.tmp, "nb.ipynb")
        _write_notebook(p, [
            {"cell_type": "code", "source": "a\nb\nc\nd\ne\nf"},
        ])
        res = json.loads(read_file_tool(p, offset=1, limit=2))
        self.assertTrue(res.get("truncated"))
        self.assertIn("offset=3", res.get("hint", ""))
        # Only first 2 lines present.
        self.assertIn("1|# ── Code cell 1 ──", res["content"])

    def test_corrupt_docx_falls_through_to_binary_guard(self):
        p = os.path.join(self.tmp, "bad.docx")
        with open(p, "wb") as fh:
            fh.write(b"not a zip")
        res = json.loads(read_file_tool(p))
        # Should NOT crash; falls through to the binary-extension guard.
        self.assertIn("error", res)
        self.assertIn("binary", res["error"].lower())

    def test_docx_read_extracts(self):
        p = os.path.join(self.tmp, "d.docx")
        _write_docx(p, (f'<?xml version="1.0"?><w:document xmlns:w="{_NS_W}">'
                        '<w:body><w:p><w:r><w:t>Report body</w:t></w:r></w:p>'
                        '</w:body></w:document>'))
        res = json.loads(read_file_tool(p))
        self.assertTrue(res.get("extracted_document"))
        self.assertIn("Report body", res["content"])


@pytest.fixture
def pdf_task(tmp_path, monkeypatch):
    from tools.terminal_tool import register_task_env_overrides, cleanup_vm

    task_id = f"pdf-{tmp_path.name}"
    monkeypatch.setenv("TERMINAL_ENV", "local")
    register_task_env_overrides(task_id, {"cwd": str(tmp_path), "env_type": "local"})
    try:
        yield task_id
    finally:
        cleanup_vm(task_id)


@pytest.mark.parametrize("suffix", [".pdf", ".PDF"])
def test_pdf_text_and_paging(tmp_path, pdf_task, suffix):
    path = tmp_path / f"document{suffix}"
    pages = [["First line", "Second line"], ["Third line", "Fourth line"]]
    _write_pdf(path, pages)
    expected = [line for page in pages for line in page]

    assert extract_document_text(str(path)).splitlines() == expected
    # Exercise real path resolution, extraction and formatting under the
    # suite's isolated HERMES_HOME, without mocking file operations.
    first = json.loads(read_file_tool(path.name, limit=2, task_id=pdf_task))
    second = json.loads(read_file_tool(path.name, offset=3, limit=2, task_id=pdf_task))
    for result in (first, second):
        assert result["extracted_document"] is True
        assert result["total_lines"] == len(expected)
        assert result["file_size"] == path.stat().st_size
    assert first["content"].splitlines() == ["1|First line", "2|Second line"]
    assert first["truncated"] is True
    assert "offset=3" in first["hint"]
    assert second["content"].splitlines() == ["3|Third line", "4|Fourth line"]
    assert second["truncated"] is False
    assert "hint" not in second
    beyond = json.loads(read_file_tool(str(path), offset=5, limit=2, task_id=pdf_task))
    assert beyond["content"] == ""
    assert beyond["truncated"] is False
    assert beyond["total_lines"] == len(expected)


@pytest.mark.parametrize("kind", ["image", "blank", "encrypted"])
def test_pdf_no_extractable_text(tmp_path, kind):
    path = tmp_path / f"{kind}.pdf"
    _write_pdf(
        path,
        [["Protected text"]] if kind == "encrypted" else [[]],
        image_only=kind == "image",
        password="test-password" if kind == "encrypted" else None,
    )
    with pytest.raises(ExtractionError, match="no extractable text"):
        extract_document_text(str(path))
    result = json.loads(read_file_tool(str(path)))
    assert "no extractable text" in result["error"].lower()
    if kind == "encrypted":
        assert "encrypted" in result["error"].lower()
    else:
        assert "OCR" in result["error"]
    assert "content" not in result


def test_malformed_pdf_error(tmp_path):
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-1.4\nnot a complete PDF")
    with pytest.raises(ExtractionError, match="Cannot extract PDF text"):
        extract_document_text(str(path))
    result = json.loads(read_file_tool(str(path)))
    assert "Cannot extract PDF text" in result["error"]


def test_pdf_respects_character_limit(tmp_path, pdf_task, monkeypatch):
    path = tmp_path / "large.pdf"
    _write_pdf(path, [["A" * 100, "Short line"]])
    monkeypatch.setattr("tools.file_tools._max_read_chars_cached", 50)

    oversized = json.loads(read_file_tool(str(path), task_id=pdf_task))
    assert "safety limit" in oversized["error"]
    assert "offset and limit" in oversized["error"]
    smaller = json.loads(read_file_tool(str(path), offset=2, limit=1, task_id=pdf_task))
    assert smaller["content"] == "2|Short line"


def test_pdf_size_cap_before_parsing(tmp_path, monkeypatch):
    path = tmp_path / "oversized.pdf"
    # Invalid bytes prove the size refusal happens before parsing.
    path.write_bytes(b"not a PDF" * 20)
    monkeypatch.setattr("tools.read_extract.MAX_PDF_BYTES", 100, raising=False)
    with pytest.raises(ExtractionError, match=r"PDF too large.*100 bytes"):
        extract_document_text(str(path))


def test_pdf_page_cap_before_text_extraction(tmp_path, monkeypatch):
    path = tmp_path / "pages.pdf"
    # Blank pages would produce the no-text error if extraction started.
    _write_pdf(path, [[], []])
    monkeypatch.setattr("tools.read_extract.MAX_PDF_PAGES", 1, raising=False)
    with pytest.raises(ExtractionError, match=r"PDF has too many pages.*1 pages"):
        extract_document_text(str(path))


def test_pdf_empty_user_password_is_readable(tmp_path):
    path = tmp_path / "protected.pdf"
    _write_pdf(path, [["Owner protected text"]], password="", owner_password="owner-secret")
    assert extract_document_text(str(path)) == "Owner protected text\n"
    _write_pdf(path, [["Private text"]], password="user-secret", owner_password="owner-secret")
    with pytest.raises(ExtractionError, match="no extractable text: the document is encrypted"):
        extract_document_text(str(path))


def test_pdf_blocked_path_never_extracted(tmp_path, pdf_task, monkeypatch):
    from pathlib import Path

    path = Path(os.environ["HERMES_HOME"]) / "skills" / ".hub" / "hidden.pdf"
    path.parent.mkdir(parents=True)
    _write_pdf(path, [["Untrusted hub instructions"]])
    calls = []

    def track_extraction(path):
        calls.append(path)
        return "Untrusted hub instructions\n"

    monkeypatch.setattr("tools.read_extract.extract_document_text", track_extraction)
    result = json.loads(read_file_tool(str(path), task_id=pdf_task))
    assert "error" in result
    assert "internal" in result["error"].lower()
    assert calls == []


def test_pdf_broken_page_content_is_extraction_error(tmp_path):
    path = tmp_path / "broken-content.pdf"
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({
            NameObject("/F1"): DictionaryObject({
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }),
        }),
    })
    # Valid PDF structure, but Tf has an array instead of a font name.
    stream = DecodedStreamObject()
    stream.set_data(b"BT [] 12 Tf (text) Tj ET")
    page[NameObject("/Contents")] = stream
    writer.write(path)
    with pytest.raises(ExtractionError, match="Cannot extract PDF text"):
        extract_document_text(str(path))


def test_missing_pdf_uses_normal_not_found(tmp_path, pdf_task):
    result = json.loads(read_file_tool("missing.pdf", task_id=pdf_task))
    assert result["error"].startswith("File not found:")
    assert "Cannot extract PDF" not in result["error"]
    assert "extracted_document" not in result


def test_pdf_total_processing_budget(tmp_path, monkeypatch):
    path = tmp_path / "shared-stream.pdf"
    _write_pdf(path, [["12345"]])
    writer = PdfWriter(clone_from=path)
    page = writer.pages[0]
    for _ in range(3):
        writer.add_page(page)  # Reuse the same content stream across pages.
    writer.write(path)
    monkeypatch.setattr("tools.file_tools._max_read_chars_cached", 1)
    assert extract_document_text(str(path)) == (
        "12345\n12345\n[extraction truncated: PDF exceeds processing budget]\n"
    )


@pytest.mark.parametrize("backend", ["docker", "ssh", "modal", "daytona", "singularity"])
def test_remote_task_never_extracts_host_pdf(tmp_path, monkeypatch, backend):
    from tools.terminal_tool import register_task_env_overrides, clear_task_env_overrides

    path = tmp_path / "host-only.pdf"
    _write_pdf(path, [["Host private text"]])
    task_id = f"remote-pdf-{backend}"
    monkeypatch.setenv("TERMINAL_ENV", backend)
    register_task_env_overrides(task_id, {"cwd": str(tmp_path)})
    calls = []

    def track_extraction(path):
        calls.append(path)
        raise ExtractionError("Host extraction attempted")

    monkeypatch.setattr("tools.read_extract.extract_document_text", track_extraction)
    try:
        result = json.loads(read_file_tool(str(path), task_id=task_id))
        assert "Cannot read binary file" in result["error"]
        assert calls == []
    finally:
        clear_task_env_overrides(task_id)


@pytest.mark.parametrize("error_name, reason", [
    ("FileNotFoundError", "file not found"),
    ("PermissionError", "permission denied"),
    ("LimitReachedError", "exceeds processing limits"),
    ("PdfReadError", "malformed or unsupported PDF"),
    ("DependencyError", "malformed or unsupported PDF"),
    ("ValueError", "malformed or unsupported PDF"),
    ("KeyError", "malformed or unsupported PDF"),
    ("TypeError", "malformed or unsupported PDF"),
    ("AttributeError", "malformed or unsupported PDF"),
    ("IndexError", "malformed or unsupported PDF"),
    ("ZeroDivisionError", "malformed or unsupported PDF"),
    ("RecursionError", "malformed or unsupported PDF"),
])
def test_pdf_errors_hide_paths_and_parser_details(
    tmp_path, pdf_task, monkeypatch, caplog, error_name, reason,
):
    import builtins
    import pypdf.errors

    path = tmp_path / "private.pdf"
    _write_pdf(path, [["text"]])
    error_type = getattr(builtins, error_name, None) or getattr(pypdf.errors, error_name)

    def fail_reader(*args, **kwargs):
        raise error_type(f"private parser detail: {path}")

    monkeypatch.setattr("pypdf.PdfReader", fail_reader)
    caplog.set_level("DEBUG", logger="tools.read_extract")
    expected = f"Cannot extract PDF text: {reason}."
    with pytest.raises(ExtractionError) as caught:
        extract_document_text(str(path))
    assert str(path) not in str(caught.value)
    assert str(caught.value) == expected
    assert "private parser detail" in caplog.text
    if error_name != "FileNotFoundError":
        result = json.loads(read_file_tool(str(path), task_id=pdf_task))
        assert result["error"] == expected


def test_pdf_redacts_credentials(tmp_path, pdf_task, monkeypatch):
    path = tmp_path / "credentials.pdf"
    credential = "sk-proj-abc123def456ghi789jkl012"
    _write_pdf(path, [[f"Key: {credential}", "Public text"]])
    monkeypatch.setattr("agent.redact._REDACT_ENABLED", True)

    result = json.loads(read_file_tool(str(path), task_id=pdf_task))
    assert credential not in result["content"]
    assert "redacted" in result["content"]
    assert "Public text" in result["content"]


if __name__ == "__main__":
    unittest.main()
