"""The README's demo GIF replays a real run, so everything it shows must come from that run."""

from demo_gif import RUN, SCENES, frames, normalize, screen_lines, transcript_text


def test_every_line_the_demo_shows_is_in_the_kept_transcript():
    text = transcript_text(RUN)
    assert [line for kind, line in SCENES if normalize(line) not in text] == []


def test_a_line_the_run_never_printed_would_be_caught():
    assert normalize("serial RK26-XOR7-ROL3-B") not in transcript_text(RUN)


def test_commands_are_matched_with_the_skill_path_shortened():
    assert "python3 scripts/make_report.py" in transcript_text(RUN)


def test_the_demo_stays_short():
    seconds = sum(milliseconds for _, _, milliseconds in frames()) / 1000
    assert 15 < seconds < 45


def test_long_lines_wrap_with_an_indent():
    first, second = screen_lines("user", "word " * 30)
    assert first[1].startswith("you › word")
    assert second[1].startswith(" " * len("you › ") + "word")
