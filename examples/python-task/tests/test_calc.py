from calc import add, is_positive

def test_add():
    assert add(2, 3) == 5
    assert add(-1, 1) == 0
    assert add(10, -4) == 6

def test_is_positive():
    assert is_positive(1) is True
    assert is_positive(0) is False
    assert is_positive(-3) is False
