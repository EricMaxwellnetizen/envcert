from envicert.utils.dockerfile import copy_sources, image_ref_pinned, parse_dockerfile
from envicert.utils.files import dockerignore_match


def test_parse_continuations_and_comments():
    df = parse_dockerfile("# comment\nFROM python:3.12 \\\n  AS base\nRUN echo a && \\\n echo b\nUSER nobody\n")
    assert [i.name for i in df.instructions] == ["FROM", "RUN", "USER"]
    assert df.froms[0].line == 2


def test_copy_sources_flags_and_json():
    df = parse_dockerfile('FROM x:1\nCOPY --chown=app:app src/ /app/\nCOPY ["a.txt", "b.txt", "/dest/"]\nADD https://x/y /tmp/y\n')
    s, d = copy_sources(df.instructions[1])
    assert s == ["src/"] and d == "/app/"
    s, d = copy_sources(df.instructions[2])
    assert s == ["a.txt", "b.txt"] and d == "/dest/"
    s, d = copy_sources(df.instructions[3])
    assert s == ["https://x/y"]


def test_image_ref_pinned():
    assert image_ref_pinned("python:3.12@sha256:abc") == (True, True)
    assert image_ref_pinned("python:3.12") == (False, True)
    assert image_ref_pinned("python:latest") == (False, False)
    assert image_ref_pinned("python") == (False, False)


def test_dockerignore():
    pats = [".git", "*.pyc", "!keep.pyc", "solution/"]
    assert dockerignore_match(".git/config", pats)
    assert dockerignore_match("a/b.pyc", pats) or dockerignore_match("b.pyc", pats)
    assert not dockerignore_match("keep.pyc", pats)
    assert dockerignore_match("solution/solve.sh", pats)
    assert not dockerignore_match("app/main.py", pats)
