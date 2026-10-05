from sentinel_pass.analyzer import analyze,leet

def test_leet_normalization(): assert leet("P@ssw0rd1!")=="passwordi i".replace(" ","")
def test_common_is_weak(): assert analyze("password").score==1
def test_long_passphrase_beats_short_complex(): assert analyze("correct horse battery staple").score>=3
def test_sequence_detected(): assert any("Sequence" in f.title for f in analyze("123456789").findings)
def test_report_is_bounded():
    r=analyze("x"*100)
    assert r.entropy<=100 and r.guesses>0
