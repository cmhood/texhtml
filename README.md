# `texhtml` -- Write HTML like LaTeX

`texhtml` compiles code from a TeX-inspired language into HTML, so that
you don't have to waste all your time typing XML tags.

## Building

Compile the program using `make`.  There is a debug build (`make debug`)
and a release build (`make texhtml`).

The program has no dependencies other than the standard library.

### Installation

You can install and uninstall the program with `make install` and
`make uninstall`, respectively.  All this does is copy the executable to
`/usr/local/bin`.

## Usage

The program always reads from stdin and writes to stdout.  No command
line arguments are accepted.

```
./texhtml <input >output
```

## The language

The language is simple to use.  Like LaTeX, each block of text separated
by two line breaks will be treated as a paragraph.  Text will be
automatically enclosed in `<p>` tags.

### Tags

Within each paragraph, you can use commands to denote inline tags, e.g.
`\font[color="red"]{text}` for red text.

All HTML tags are supported.  In fact, the compiler does not know what
is or is not a valid HTML tag.  It handles all of them the same way:

  * Anything enclosed in square brackets after a command will be treated
    as element attributes: `\a[href="/"]{click}` becomes
    `<a href="/">click</a>`.
  * If the curly braces are omitted, the element will be treated as an
    "empty" element: `Image \img[src="foo.jpg"] with text after it`
    becomes `<img src="foo.jpg" />`.

### Different enclosing tags for sections

If you don't want a section to be wrapped in a `<p>` tag, you can start
a section with a command, e.g.:

```
This is a normal paragraph.\ It is followed by a list:

\.ul
\li{One}
\li{Two}
```

The tag name in the command must be preceded by a `.` character to
produce this behavior.

### Empty-element sections

For a section which contains just an empty elements, you can replace
the `.` with a `?`.  Then the section cannot contain any content
other than that element.

```
Look at this cool image:

\?img[src="foo.jpg"]

Wow!
```

### Verbatim blocks

Additionally, verbatim blocks are permitted in two forms.  Like in
Markdown, a sequence of three backticks (```` ``` ````) will start a
verbatim string, which is then terminated by the same sequence.  This
can be used in combination with HTML's `<pre>` tag.

The other way is by putting a backtick before the tag name in a command,
e.g. ``\`code{...}``.

### Lexical substitutions

The compiler will perform certain lexical subsitutions, such as
converting a sequence of two hyphens into an en dash, or escaping HTML
(as well as `texhtml`) characters.

A full list of substitutions can be found in the source code.

### En spaces

One special feature is the ability to use en spaces between sentences.
Since it is ambiguous in some cases whether a space is separating two
sentences or only two words, all en spaces must be marked with a
backslash.

This differs significantly from how LaTeX handles spaces, but it is
much simpler and more reliable.  LaTeX has an elaborate set of rules
for determining whether a period is marking the end of a sentence or
just an abbreviation, but it still gets it wrong a lot of the time,
requiring manual control anyway.

## Implementation

The compiler is implemented with a simple recursive-descent parser.
Perhaps anomalously, the compiler does not generate a syntax tree while
parsing.  Instead, the parser generates the HTML output as it goes,
backtracking by simply overwriting its previous output.  This
greatly reduces the program complexity, as the manner in which any given
language component is translated can be described entirely within a
single function.

Presumably, this technique also significantly improves performance,
relative to other recursive-descent parsers; however, that is not a
goal.
