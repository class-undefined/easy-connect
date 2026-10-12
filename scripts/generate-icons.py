"""Generate repository-owned square PNG, ICNS and ICO artwork without dependencies."""
import pathlib
import struct
import zlib


def chunk(name, body):
    return struct.pack(">I", len(body)) + name + body + struct.pack(">I", zlib.crc32(name + body))


def png(size):
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            a, b = x / size, y / size
            border = 0.17 <= a <= 0.83 and 0.17 <= b <= 0.83 and (
                a < 0.23 or a > 0.77 or b < 0.23 or b > 0.77
            )
            line = 0.29 <= a <= 0.71 and 0.45 <= b <= 0.52
            mark = 0.41 <= a <= 0.59 and 0.63 <= b <= 0.70
            rows.extend((34, 211, 176, 255) if border or line or mark else (16, 23, 32, 255))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


if __name__ == "__main__":
    assets = pathlib.Path(__file__).resolve().parent.parent / "assets"
    assets.mkdir(exist_ok=True)
    assets.joinpath("icon.png").write_bytes(png(256))
    entries = b"".join(name + struct.pack(">I", len(image) + 8) + image
                       for name, image in [(b"ic08", png(256)), (b"ic09", png(512)), (b"ic10", png(1024))])
    assets.joinpath("EasyConnect.icns").write_bytes(b"icns" + struct.pack(">I", len(entries) + 8) + entries)
    image = png(256)
    assets.joinpath("icon.ico").write_bytes(struct.pack("<HHH", 0, 1, 1)
        + struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(image), 22) + image)
