from pathlib import Path

def test_hello_file_content():
    p = Path("/app/hello.txt")
    assert p.is_file(), "hello.txt missing"
    assert p.read_text(encoding="utf-8") == "hello envicert\n"

def test_hello_file_is_not_empty_placeholder():
    text = Path("/app/hello.txt").read_text(encoding="utf-8").strip().lower()
    assert text not in ("", "todo", "hello world")
    assert len(text) == len("hello envicert")
