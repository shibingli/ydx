# Glyph bitmap atlas | 字形位图图集

`glyphs.bin` contains 32x32 8-bit alpha masks rendered from
**Noto Sans CJK SC Regular** (`NotoSansCJKsc-Regular.otf`) for the curated
Latin, digit and common Chinese character set used by the built-in challenges.
Only the rendered bitmap data is distributed here; the font file itself is not
included.

The source font is licensed under the SIL Open Font License 1.1. The full
license text is in [`OFL.txt`](OFL.txt).

`glyphs.bin` 包含由 **Noto Sans CJK SC Regular** 渲染的 32x32 8 位阿尔法掩码，
覆盖内置挑战使用的拉丁字母、数字与常用汉字。这里只分发渲染后的位图数据，不包含字体
文件本身。字体使用 SIL Open Font License 1.1，完整许可证见 [`OFL.txt`](OFL.txt)。

格式 | Format:

```text
"YDXG" | uint16 version (1) | uint16 count
repeat count times: uint32 rune | 1024 bytes alpha (32x32)
```
