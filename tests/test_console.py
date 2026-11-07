"""Console output: progress lines, stage column layout and the results screen."""
from __future__ import annotations

import logging

from test_report_notify_cli import COVERAGE, EOL, FINDINGS

from vulnscan import cli, svn, util


# --- progress ---------------------------------------------------------------------------
def test_progress_text_never_goes_past_the_end():
    text = util.progress_text(3155, 2933, 10)
    assert text.startswith("100.0%") and "2,933 / 2,933" in text and "ETA" not in text


def test_progress_text_with_sizes_rate_and_eta():
    text = util.progress_text(1024 ** 3, 4 * 1024 ** 3, 60, size=True, rate=True)
    assert " 25.0%" in text and "1.0 GB / 4.0 GB" in text and "17.1 MB/s" in text and "ETA 3:00" in text


def test_progress_text_without_a_total():
    assert util.progress_text(12, 0, 5) == "12 so far"


def _listing(*files: tuple[str, int]) -> str:
    entries = "".join(f'<entry kind="file"><name>{n}</name><size>{s}</size></entry>' for n, s in files)
    return f'<?xml version="1.0"?><lists><list path="x"><entry kind="dir"><name>bin</name></entry>{entries}</list></lists>'


def test_parse_listing_keeps_files_only():
    assert svn.parse_listing(_listing(("bin/a.dll", 100), ("b c.txt", 7))) == {"bin/a.dll": 100, "b c.txt": 7}


def test_checkout_progress_counts_listed_files_not_directories(tmp_path):
    """Regression: bytes came from the disk, where svn had not written the file yet (<1 KB/s),
    and directories were counted as files (68,529 / 62,581)."""
    p = svn.CheckoutProgress(tmp_path, "svn:demo")
    p.added(str(tmp_path / "bin"))            # directory, announced before the listing arrives
    p.added(str(tmp_path / "bin" / "a.dll"))  # file, not on disk yet
    assert "measuring repository size" in p.text()
    p.sizes = svn.parse_listing(_listing(("bin/a.dll", 3 * 1024 ** 2), ("bin/b.dll", 1024 ** 2)))
    p.added(str(tmp_path / "bin" / "b.dll"))
    assert (p.files, p.bytes) == (2, 4 * 1024 ** 2)
    assert "100.0%" in p.text() and "2 / 2 files" in p.text()


# --- stage column -----------------------------------------------------------------------
def _render(stage: str, msg: str, level=logging.INFO) -> str:
    rec = logging.LogRecord("vulnscan", level, __file__, 1, msg, None, None)
    rec.stage = stage
    with util.console.capture() as cap:
        util.RichLineHandler().emit(rec)
    return cap.get()


def test_stage_column_is_sized_once_for_the_whole_run():
    util.set_stage_width(["com_2026", "plugins_2026"])
    try:
        short, long_ = _render("svn:com_2026", "hello"), _render("stage:plugins_2026", "hello")
        assert short.index("hello") == long_.index("hello")  # no jump between sections
        warn = _render("svn:com_2026", "hello", logging.WARNING)
        assert util.MARK_WARN in warn and warn.index("hello") == short.index("hello")
    finally:
        util.set_stage_width([])


def test_overlong_stage_tags_are_truncated_not_shifted():
    util.set_stage_width(["x" * 80])
    try:
        assert _render("stage:" + "x" * 80, "msg").index("msg") == _render("db", "msg").index("msg")
    finally:
        util.set_stage_width([])


def test_log_marks_have_no_emoji_presentation():
    # emoji-capable symbols (Unicode Emoji=Yes) that terminals tend to draw two cells wide:
    # the Miscellaneous Symbols block plus the ones vulnscan used before (play, check, cross)
    emoji = {0x25B6, 0x25C0, 0x2705, 0x2714, 0x2716, 0x274C, 0x2757}
    for mark in (util.MARK_WARN, util.MARK_ERROR, util.MARK_START, util.MARK_DONE):
        assert len(mark) == 1 and ord(mark) not in emoji and not 0x2600 <= ord(mark) <= 0x26FF


# --- results screen ---------------------------------------------------------------------
def test_results_screen_has_separate_kev_and_eol_sections():
    s = cli.summarize([dict(f) for f in FINDINGS], COVERAGE, EOL, ["r1"])
    assert s["eol_items"] == [{"product": "python", "version": "3.8.10", "files": 1, "eol_date": "2024-10-07"}]
    with util.console.capture() as cap:
        cli.final_summary(s, "./report.xlsx", "./evidence", "1:23")
    out = cap.get()
    assert "INCOMPLETE" in out and "4 findings in 10 files" in out
    kev, eol = out.index("Actively exploited (1)"), out.index("End-of-life components (1)")
    assert kev < out.index("CVE-2025-0411") < eol < out.index("3.8.10")
    assert "./report.xlsx" in out


def test_results_screen_totals_row_for_several_repositories():
    cov = [dict(COVERAGE[0], engines={}, archives_failed=0), dict(COVERAGE[0], repo="r2", engines={},
                                                                   archives_failed=0)]
    s = cli.summarize([dict(f) for f in FINDINGS], cov, [], ["r1", "r2"])
    with util.console.capture() as cap:
        cli.final_summary(s, "r.xlsx", "e", "0:01")
    out = cap.get()
    assert "COMPLETE" in out and "Total" in out and "20" in out
