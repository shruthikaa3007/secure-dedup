from __future__ import annotations

from math import atan2, cos, sin
from pathlib import Path
import shutil

from PIL import Image, ImageDraw, ImageFont


WIDTH = 1800
HEIGHT = 1100
BG = (249, 248, 244)
TEXT = (32, 38, 46)
ARROW = (55, 59, 66)

REPO_OUT = Path(r"E:\secure-dedup\docs\diagrams\fig_architecture_aligned.png")
DOWNLOADS_OUT = Path(r"C:\Users\Shruthikaa\Downloads\fig_architecture.png")
DOWNLOADS_VERSIONED = Path(r"C:\Users\Shruthikaa\Downloads\fig_architecture_aligned.png")
WORD_DOC = Path(r"C:\Users\Shruthikaa\Downloads\Team44_Complete fin.docx")


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = []
    if bold:
        candidates.extend(
            [
                Path(r"C:\Windows\Fonts\arialbd.ttf"),
                Path(r"C:\Windows\Fonts\seguisb.ttf"),
                Path(r"C:\Windows\Fonts\segoeuib.ttf"),
            ]
        )
    else:
        candidates.extend(
            [
                Path(r"C:\Windows\Fonts\arial.ttf"),
                Path(r"C:\Windows\Fonts\segoeui.ttf"),
                Path(r"C:\Windows\Fonts\calibri.ttf"),
            ]
        )

    for path in candidates:
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


FONT_TITLE = load_font(29, bold=True)
FONT_MODULE = load_font(24, bold=True)
FONT_BOX = load_font(22, bold=True)
FONT_BODY = load_font(20)
FONT_LABEL = load_font(18, bold=True)


def wrap_text(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont, max_width: int) -> list[str]:
    lines: list[str] = []
    for raw_line in text.split("\n"):
        words = raw_line.split()
        if not words:
            lines.append("")
            continue
        current = words[0]
        for word in words[1:]:
            trial = f"{current} {word}"
            width = draw.textbbox((0, 0), trial, font=font)[2]
            if width <= max_width:
                current = trial
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines


def draw_centered_text(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    text: str,
    font: ImageFont.ImageFont,
    fill: tuple[int, int, int] = TEXT,
    line_gap: int = 6,
) -> None:
    x1, y1, x2, y2 = box
    lines = wrap_text(draw, text, font, x2 - x1 - 24)
    heights = []
    widths = []
    for line in lines:
        left, top, right, bottom = draw.textbbox((0, 0), line, font=font)
        widths.append(right - left)
        heights.append(bottom - top)

    total_height = sum(heights) + line_gap * max(0, len(lines) - 1)
    y = y1 + ((y2 - y1) - total_height) / 2
    for line, width, height in zip(lines, widths, heights):
        x = x1 + ((x2 - x1) - width) / 2
        draw.text((x, y), line, font=font, fill=fill)
        y += height + line_gap


def rounded_box(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    fill: tuple[int, int, int],
    outline: tuple[int, int, int],
    radius: int = 28,
    width: int = 3,
    text: str | None = None,
    title: bool = False,
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)
    if text:
        font = FONT_MODULE if title else FONT_BOX
        draw_centered_text(draw, box, text, font)


def draw_module_container(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    fill: tuple[int, int, int],
    outline: tuple[int, int, int],
    title: str,
) -> None:
    rounded_box(draw, box, fill, outline, radius=46, width=3)
    title_box = (box[0] + 20, box[1] + 10, box[2] - 20, box[1] + 60)
    draw_centered_text(draw, title_box, title, FONT_MODULE)


def draw_arrow(
    draw: ImageDraw.ImageDraw,
    points: list[tuple[int, int]],
    label: str | None = None,
    label_offset: tuple[int, int] = (0, 0),
    color: tuple[int, int, int] = ARROW,
    width: int = 4,
) -> None:
    draw.line(points, fill=color, width=width)
    (x1, y1), (x2, y2) = points[-2], points[-1]
    angle = atan2(y2 - y1, x2 - x1)
    head_len = 16
    wing = 7
    left = (
        x2 - head_len * cos(angle) + wing * sin(angle),
        y2 - head_len * sin(angle) - wing * cos(angle),
    )
    right = (
        x2 - head_len * cos(angle) - wing * sin(angle),
        y2 - head_len * sin(angle) + wing * cos(angle),
    )
    draw.polygon([(x2, y2), left, right], fill=color)

    if label:
        mid = points[len(points) // 2]
        lx = mid[0] + label_offset[0]
        ly = mid[1] + label_offset[1]
        tw = draw.textbbox((0, 0), label, font=FONT_LABEL)[2]
        th = draw.textbbox((0, 0), label, font=FONT_LABEL)[3]
        pad = 8
        draw.rounded_rectangle(
            (lx - pad, ly - pad, lx + tw + pad, ly + th + pad),
            radius=10,
            fill=(255, 255, 255),
            outline=None,
        )
        draw.text((lx, ly), label, font=FONT_LABEL, fill=TEXT)


def replace_word_architecture_image(docx_path: Path, image_path: Path) -> None:
    import zipfile

    tmp = docx_path.with_name(docx_path.stem + ".__arch_tmp__.docx")
    with zipfile.ZipFile(docx_path, "r") as zin, zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "word/media/image2.png":
                data = image_path.read_bytes()
            zout.writestr(item, data)
    try:
        if docx_path.exists():
            docx_path.unlink()
        shutil.move(str(tmp), str(docx_path))
    except PermissionError:
        if tmp.exists():
            tmp.unlink()
        raise


def main() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)

    draw_centered_text(
        draw,
        (120, 10, WIDTH - 120, 70),
        "Secure Cloud Deduplication Framework with Behavioural Monitoring",
        FONT_TITLE,
    )

    interface = (40, 80, 590, 500)
    core = (620, 80, 1180, 560)
    security = (1210, 80, 1760, 560)
    behavior = (160, 620, 1030, 1040)

    draw_module_container(draw, interface, (219, 232, 248), (73, 116, 184), "Interface Module")
    draw_module_container(draw, core, (252, 244, 220), (208, 155, 33), "Core Deduplication Module")
    draw_module_container(draw, security, (251, 229, 229), (210, 87, 74), "Security and Control Module")
    draw_module_container(draw, behavior, (236, 225, 248), (123, 88, 168), "Behaviour Detection Module")

    rounded_box(draw, (70, 160, 270, 280), (197, 219, 246), (85, 125, 193), text="Client Applications / SDK")
    rounded_box(
        draw,
        (310, 145, 530, 300),
        (197, 219, 246),
        (85, 125, 193),
        text="FastAPI API + Auth\n/upload\n/pow/challenge\n/pow/verify",
    )
    rounded_box(
        draw,
        (160, 350, 460, 460),
        (225, 238, 252),
        (85, 125, 193),
        text="Telemetry Logger\nCSV + SQLite event store",
    )

    rounded_box(draw, (660, 155, 860, 265), (255, 239, 191), (215, 171, 47), text="FastCDC\nChunking")
    rounded_box(
        draw,
        (910, 155, 1130, 265),
        (255, 239, 191),
        (215, 171, 47),
        text="HMAC-SHA256\nToken Generation",
    )
    rounded_box(
        draw,
        (705, 320, 930, 430),
        (255, 244, 214),
        (215, 171, 47),
        text="Redis Dedup Index\nRef Count / O(1) Lookup",
    )
    rounded_box(
        draw,
        (955, 320, 1140, 430),
        (214, 237, 216),
        (77, 150, 91),
        text="Ristretto255 OPRF\nHKDF\nAES-256-GCM",
    )
    rounded_box(
        draw,
        (790, 460, 1070, 530),
        (214, 237, 216),
        (77, 150, 91),
        text="Storage Adapter\nS3 / MinIO / Local FS",
    )

    rounded_box(draw, (1260, 155, 1510, 275), (239, 239, 239), (128, 128, 128), text="Reputation Manager")
    rounded_box(
        draw,
        (1260, 320, 1510, 445),
        (253, 215, 215),
        (210, 87, 74),
        text="Adaptive PoW Engine\nrisk + reputation +\nduplicate pressure",
    )
    rounded_box(
        draw,
        (1540, 155, 1730, 285),
        (239, 239, 239),
        (128, 128, 128),
        text="Redis Policy /\nReputation Cache",
    )
    rounded_box(
        draw,
        (1540, 320, 1730, 445),
        (253, 215, 215),
        (210, 87, 74),
        text="Policy Engine\nALLOW /\nRATE_LIMIT /\nBLOCK",
    )

    rounded_box(
        draw,
        (230, 720, 500, 840),
        (228, 211, 244),
        (123, 88, 168),
        text="Feature Extraction\n12 behavioural signals",
    )
    rounded_box(
        draw,
        (570, 710, 900, 860),
        (228, 211, 244),
        (123, 88, 168),
        text="Detector\nSupervised RF\nCold-start OCSVM\nrisk score r, label y-hat",
    )
    rounded_box(
        draw,
        (330, 900, 700, 1000),
        (245, 242, 248),
        (140, 140, 140),
        text="Model Artifacts\nsupervised + cold-start artefacts",
    )

    draw_arrow(draw, [(270, 220), (310, 220)])
    draw_arrow(draw, [(530, 220), (660, 220)])
    draw_arrow(draw, [(860, 220), (910, 220)])
    draw_arrow(draw, [(1020, 265), (1020, 320), (1020, 320)], label="new chunk", label_offset=(18, -48))
    draw_arrow(draw, [(1138, 375), (1228, 375), (1260, 382)], label="duplicate token", label_offset=(-10, -48))
    draw_arrow(draw, [(1045, 430), (1045, 460)])

    draw_arrow(draw, [(420, 300), (420, 350)], label="request logs", label_offset=(10, -48))
    draw_arrow(draw, [(460, 405), (460, 780), (500, 780)])
    draw_arrow(draw, [(500, 780), (570, 780)])
    draw_arrow(draw, [(700, 950), (735, 950), (735, 860)])

    draw_arrow(draw, [(900, 760), (1210, 760), (1210, 215), (1260, 215)], label="risk / label", label_offset=(18, -34))
    draw_arrow(draw, [(900, 790), (1480, 790), (1480, 382), (1540, 382)], label="policy input r", label_offset=(18, -34))
    draw_arrow(draw, [(1510, 215), (1510, 382), (1510, 382)])
    draw_arrow(
        draw,
        [(1730, 382), (1755, 382), (1755, 590), (530, 590), (530, 300)],
        label="ALLOW / RATE_LIMIT / BLOCK",
        label_offset=(-220, -34),
    )
    draw_arrow(draw, [(1510, 382), (1540, 382)])
    draw_arrow(draw, [(1540, 230), (1730, 230)])

    REPO_OUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(REPO_OUT, format="PNG")
    shutil.copy2(REPO_OUT, DOWNLOADS_OUT)
    shutil.copy2(REPO_OUT, DOWNLOADS_VERSIONED)

    if WORD_DOC.exists():
        try:
            replace_word_architecture_image(WORD_DOC, REPO_OUT)
        except PermissionError:
            print(f"WORD_DOC_LOCKED={WORD_DOC}")


if __name__ == "__main__":
    main()
