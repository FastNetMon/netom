//! Table rendering.
//!
//! Two modes, because the two kinds of response need different things:
//!
//! * [`Table::fit`] buffers rows and sizes each column to its widest cell.
//!   Used for bounded responses (neighbor lists, status).
//! * [`Table::fixed`] writes rows as they arrive, using the declared column
//!   widths. Required for streamed NDJSON, where the rows cannot be
//!   pre-scanned. An oversized cell is printed in full and shifts the rest
//!   of *that* row right, which is what a router does — truncating routing
//!   data to preserve alignment would be the wrong trade.

pub mod fmt;

use std::io::{self, Write};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

pub struct Col {
    pub title: &'static str,
    /// Minimum width in `Fit` mode; the actual width in `Fixed` mode.
    pub width: usize,
    pub align: Align,
}

pub const fn left(title: &'static str, width: usize) -> Col {
    Col {
        title,
        width,
        align: Align::Left,
    }
}

pub const fn right(title: &'static str, width: usize) -> Col {
    Col {
        title,
        width,
        align: Align::Right,
    }
}

enum Mode {
    Fixed,
    Fit(Vec<Vec<String>>),
}

pub struct Table<'a, W: Write> {
    out: &'a mut W,
    cols: &'static [Col],
    mode: Mode,
    header_written: bool,
}

impl<'a, W: Write> Table<'a, W> {
    /// Streaming table: header first, rows as they arrive.
    pub fn fixed(out: &'a mut W, cols: &'static [Col]) -> Self {
        Self {
            out,
            cols,
            mode: Mode::Fixed,
            header_written: false,
        }
    }

    /// Buffered table: columns sized to content at `finish()`.
    pub fn fit(out: &'a mut W, cols: &'static [Col]) -> Self {
        Self {
            out,
            cols,
            mode: Mode::Fit(Vec::new()),
            header_written: false,
        }
    }

    pub fn row<S: AsRef<str>>(&mut self, cells: &[S]) -> io::Result<()> {
        match &mut self.mode {
            Mode::Fit(rows) => {
                rows.push(
                    cells
                        .iter()
                        .map(|c| c.as_ref().to_string())
                        .collect(),
                );
                Ok(())
            }
            Mode::Fixed => {
                if !self.header_written {
                    let widths: Vec<usize> =
                        self.cols.iter().map(|c| c.width).collect();
                    write_header(self.out, self.cols, &widths)?;
                    self.header_written = true;
                }
                let widths: Vec<usize> =
                    self.cols.iter().map(|c| c.width).collect();
                write_row(self.out, self.cols, &widths, cells)
            }
        }
    }

    /// Write a free-form line, outside the table grid.
    pub fn note(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.out, "{text}")
    }

    pub fn finish(self) -> io::Result<()> {
        let Table {
            out,
            cols,
            mode,
            header_written,
        } = self;

        match mode {
            Mode::Fixed => {
                // A streamed table with no rows still deserves its header,
                // so an empty result is visibly empty rather than blank.
                if !header_written {
                    let widths: Vec<usize> =
                        cols.iter().map(|c| c.width).collect();
                    write_header(out, cols, &widths)?;
                }
                out.flush()
            }
            Mode::Fit(rows) => {
                let mut widths: Vec<usize> = cols
                    .iter()
                    .map(|c| c.width.max(c.title.chars().count()))
                    .collect();
                for row in &rows {
                    for (i, cell) in row.iter().enumerate() {
                        if i < widths.len() {
                            widths[i] = widths[i].max(cell.chars().count());
                        }
                    }
                }
                write_header(out, cols, &widths)?;
                for row in &rows {
                    write_row(out, cols, &widths, row)?;
                }
                out.flush()
            }
        }
    }
}

fn write_header<W: Write>(
    out: &mut W,
    cols: &'static [Col],
    widths: &[usize],
) -> io::Result<()> {
    let titles: Vec<&str> = cols.iter().map(|c| c.title).collect();
    write_row(out, cols, widths, &titles)
}

fn write_row<W: Write, S: AsRef<str>>(
    out: &mut W,
    cols: &'static [Col],
    widths: &[usize],
    cells: &[S],
) -> io::Result<()> {
    let mut line = String::new();
    for (i, cell) in cells.iter().enumerate() {
        let Some(col) = cols.get(i) else { break };
        let width = widths.get(i).copied().unwrap_or(col.width);
        let text = cell.as_ref();
        // Character count, not byte length: a multi-byte cell must not
        // silently over-pad.
        let len = text.chars().count();

        if i > 0 {
            line.push(' ');
        }
        if col.align == Align::Right && len < width {
            line.push_str(&" ".repeat(width - len));
            line.push_str(text);
        } else {
            line.push_str(text);
            // Never pad the last column: trailing whitespace is noise in a
            // terminal and breaks naive diffing of golden files.
            if i + 1 < cells.len() && len < width {
                line.push_str(&" ".repeat(width - len));
            }
        }
    }
    writeln!(out, "{}", line.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    static COLS: &[Col] = &[left("Name", 8), right("Count", 6)];

    fn render(build: impl FnOnce(&mut Table<'_, Vec<u8>>)) -> String {
        let mut buf = Vec::new();
        let mut table = Table::fit(&mut buf, COLS);
        build(&mut table);
        table.finish().unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn fit_mode_aligns_columns() {
        let out = render(|t| {
            t.row(&["alpha", "1"]).unwrap();
            t.row(&["b", "22"]).unwrap();
        });
        assert_eq!(
            out,
            "Name      Count\n\
             alpha         1\n\
             b            22\n",
        );
    }

    #[test]
    fn fit_mode_widens_to_the_longest_cell() {
        let out = render(|t| {
            t.row(&["a-very-long-name", "1"]).unwrap();
        });
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("Name"));
        assert!(lines[1].starts_with("a-very-long-name"));
        // The last column is right-aligned, so its cells end in the same
        // column as the header does.
        assert_eq!(
            lines[0].chars().count(),
            lines[1].chars().count(),
            "right-aligned column not flush:\n{out}",
        );
    }

    #[test]
    fn no_trailing_whitespace_is_emitted() {
        let out = render(|t| {
            t.row(&["a", "1"]).unwrap();
        });
        for line in out.lines() {
            assert_eq!(line, line.trim_end(), "trailing space in {line:?}");
        }
    }

    #[test]
    fn an_empty_table_still_prints_its_header() {
        let out = render(|_| {});
        assert_eq!(out, "Name      Count\n");
    }

    #[test]
    fn fixed_mode_streams_the_header_before_the_first_row() {
        let mut buf = Vec::new();
        let mut t = Table::fixed(&mut buf, COLS);
        t.row(&["a", "1"]).unwrap();
        t.finish().unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("Name"));
        assert!(out.contains("\na"));
    }

    /// Routing data must never be truncated to preserve alignment.
    #[test]
    fn fixed_mode_lets_an_oversized_cell_shift_its_row() {
        let mut buf = Vec::new();
        let mut t = Table::fixed(&mut buf, COLS);
        t.row(&["this-name-is-far-too-long", "7"]).unwrap();
        t.finish().unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("this-name-is-far-too-long"));
        assert!(out.trim_end().ends_with('7'));
    }
}
