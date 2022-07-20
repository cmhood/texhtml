#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COUNT(...) (sizeof(__VA_ARGS__) / sizeof((__VA_ARGS__)[0]))

#ifdef __GNUC__
#define undefined (__builtin_unreachable())
#else
#define undefined ((void)(*(char *)NULL))
#endif

#ifdef DEBUG
#define ASSERT(COND) do { if (!(COND)) { undefined; } } while (0)
#else
#define ASSERT(COND) do { if (!(COND)) { undefined; } } while (0)
#endif

/* An input string for the parser. */
typedef struct input_ {
	size_t max_parse;
	size_t size;
	char const *data;
} input_;

/* A cursor that what point a the parser is at while parsing some input */
typedef struct input_cursor_ {
	input_ *input;
	size_t position;
} input_cursor_;

/* A dynamic array used to store the translation output. */
typedef struct output_ {
	size_t capacity;
	char *buffer;
} output_;

/* Represents the value of a "space" character, which has to be buffered
since spaces shouldn't occur more than once in a row. */
typedef enum pending_space_ {
	PENDING_SPACE_NONE, // No space in buffer
	PENDING_SPACE_PLAIN, // Plain ASCII space
	PENDING_SPACE_EN, // HTML &ensp;
	PENDING_SPACE_BLOCKED, // Block any space from being generated
} pending_space_;

/* A cursor that indicates where output should be written to inside the
dynamic buffer.  Also includes `pending_space_` for buffering space
characters. */
typedef struct output_cursor_ {
	output_ *output;
	size_t position;
	pending_space_ pending_space;
} output_cursor_;

/* A literal substitution of one string to another, used to do simple
translations while parsing.  Strings are `NUL`-terminated. */
typedef struct substitution_ {
	char const *in;
	char const *out;
} substitution_;

/* Allocate memory, without failing.  Same interface as `realloc`. */
static void *xrealloc(void *const old_ptr, size_t const size) {
	void *const ptr = realloc(old_ptr, size);
	if (ptr == NULL) {
		perror("realloc");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

/* Scans the entire contents of `fp` into a buffer.  Returns a buffer
which must be freed (with `free`) and sets `*out_size` to the size of
the buffer.  Terminates the program upon failure. */
static char *read_file(FILE *const fp, size_t *const out_size) {
	/* Instead of relying on `ftell`, we use `fread` in a loop and
	dynamically resize the buffer.  This is because `ftell` is not
	guaranteed to work on `stdin` and other FIFOs. */

	size_t buf_size = 1;
	char *buf = NULL;
	size_t off = 0;
	for (;;) {
		buf = xrealloc(buf, buf_size);
		size_t const space = buf_size - off;
		size_t const used = fread(&buf[off], 1, space, fp);
		if (used < space) {
			if (ferror(fp) != 0) {
				perror("fread");
				exit(EXIT_FAILURE);
			}
			*out_size = off + used;
			return buf;
		}
		off = buf_size;
		size_t const new_buf_size = buf_size * 2;
		if (new_buf_size <= buf_size) {
			fprintf(stderr, "Input is too large\n");
			exit(EXIT_FAILURE);
		}
		buf_size = new_buf_size;
	}
}

/* Allocates an output buffer and cursor.  Must be freed using
`destroy_output`. */
static output_cursor_ *create_output(void) {
	output_ *const output = xrealloc(NULL, sizeof(*output));
	output_cursor_ *const cursor = xrealloc(NULL, sizeof(*cursor));
	*output = (output_){ 0, NULL };
	*cursor = (output_cursor_){ output, 0, PENDING_SPACE_NONE };
	return cursor;
}

/* Creates an output buffer and cursor created by `create_output`. */
static void destroy_output(output_cursor_ *const output) {
	ASSERT(output != NULL);
	free(output->output->buffer);
	free(output->output);
	free(output);
}

/* Returns `true` iff the cursor is at the start of the input. */
static bool parse_start(input_cursor_ *const input) {
	ASSERT(input != NULL);
	return input->position == 0;
}

/* Returns `true` iff the cursor is at the end of the input. */
static bool parse_end(input_cursor_ *const input) {
	ASSERT(input != NULL);
	return input->position == input->input->size;
}

/* Scans any single byte, if not at the end of the input, and stores
it in `*c`.  Returns `true` iff the byte could be scanned. */
static bool parse_any_char(input_cursor_ *const input, char *const c) {
	ASSERT(input != NULL);
	input_cursor_ my_input = *input;

	if (parse_end(&my_input)) { return false; }
	*c = my_input.input->data[my_input.position];
	my_input.input->max_parse = my_input.position;
	++my_input.position;

	*input = my_input;
	return true;
}

/* Scans a particular byte from the input, if that is the next
byte, according to the cursor.  Returns `true` iff the desired byte
was scanned. */
static bool parse_char(input_cursor_ *const input, char const c) {
	ASSERT(input != NULL);
	input_cursor_ my_input = *input;

	char res;
	if (!parse_any_char(&my_input, &res)) { return false; }
	if (res != c) { return false; }

	*input = my_input;
	return true;
}

/* Tries to scan a `NUL`-terminated string from the input, not including the
`NUL` byte, if those characters are next, according to the cursor.
Returns `true` iff the desired string was scanned. */
static bool parse_string(input_cursor_ *const input, char const *const string) {
	ASSERT(input != NULL && string != NULL);
	input_cursor_ my_input = *input;
	for (size_t i = 0;; ++i) {
		char const c = string[i];
		if (c == '\0') {
			*input = my_input;
			return true;
		}
		if (!parse_char(&my_input, c)) { return false; }
	}
}

static void generate_char(output_cursor_ *, char);
static void generate_string(output_cursor_ *, char const *);
static void generate_pending_space(output_cursor_ *, pending_space_);

/* Writes `data`, an array of bytes, of size `data_size`, into an output
buffer, and moves the cursor to start of the empty part of the buffer.
Reallocates the buffer as necessary. */
static void generate(output_cursor_ *const output, size_t const data_size, char const *const data) {
	// Flush the pending space
	pending_space_ const ps = output->pending_space;
	generate_pending_space(output, PENDING_SPACE_NONE);
	switch (ps) {
	case PENDING_SPACE_PLAIN:
		generate_char(output, ' ');
		break;
	case PENDING_SPACE_EN:
		generate_string(output, "&ensp;");
		break;
	default:
		break;
	}
	ASSERT(output->pending_space == PENDING_SPACE_NONE);

	// Early exit if no data to write
	if (data_size == 0) { return; }

	// Resize the buffer if necessary
	size_t const output_size = output->position + data_size;
	size_t const new_capacity = 2 * output_size;
	if (output_size < data_size || new_capacity <= output_size) {
		// In case there is overflow, which should never happen in practice
		fprintf(stderr, "Output is too large");
		exit(EXIT_FAILURE);
	}
	if (output_size > output->output->capacity) {
		output->output->buffer = xrealloc(output->output->buffer, new_capacity);
		output->output->capacity = new_capacity;
	}

	// Write to the buffer
	memcpy(&output->output->buffer[output->position], data, data_size);
	output->position = output_size;
}

/* Writes a single byte into an output buffer */
static void generate_char(output_cursor_ *const output, char const c) {
	generate(output, 1, &c);
}

/* Writes a pending space into the output cursor, buffering it instead
of writting directly to the output. */
static void generate_pending_space(output_cursor_ *const output, pending_space_ const pending_space) {
	ASSERT(output != NULL);
	if (pending_space == PENDING_SPACE_NONE || output->pending_space < pending_space) {
		output->pending_space = pending_space;
	}
}

/* Writes a `NUL`-terminated string, not including the `NUL` byte, into
an output buffer. */
static void generate_string(output_cursor_ *const output, char const *const string) {
	generate(output, strlen(string), string);
}

/* Copies the contents of one output, `src`, into another output,
`output`, without altering `src`.  If `src` has a non-empty pending
space, it is ignored. */
static void generate_output(output_cursor_ *const output, output_cursor_ *const src) {
	generate(output, src->position, src->output->buffer);
}

/* Scans a literal space or control character (i.e., any byte <= ASCII
0x20) from `input`, and generates a plain space in `output`. */
static bool translate_space(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	char c;
	if (!parse_any_char(&my_input, &c)) { return false; }
	if (c > ' ') { return false; }
	generate_pending_space(&my_output, PENDING_SPACE_PLAIN);

	*input = my_input;
	*output = my_output;
	return true;
}

/* Literally translates any substitution found in the array
`substitutions` of length `subsitution_count`. */
static bool translate_substitutions(input_cursor_ *const input, output_cursor_ *const output, size_t const substitution_count, substitution_ const *const substitutions) {
	for (size_t i = 0; i < substitution_count; ++i) {
		substitution_ const subst = substitutions[i];

		/* If the subsitution input is found at the cursor position,
		scan it and generate the corresponding output */
		if (parse_string(input, subst.in)) {
			generate_string(output, subst.out);
			return true;
		}
	}
	return false;
}

/* Translates "verbatim" substitutions (considered applicable in
"verbatim" mode) from a defined list */
static bool translate_verbatim_substitutions(input_cursor_ *const input, output_cursor_ *const output) {
	static substitution_ const substitutions[] = {
		{ "&", "&amp;" },
		{ "<", "&lt;" },
		{ ">", "&gt;" },
	};
	return translate_substitutions(input, output, COUNT(substitutions), substitutions);
}

/* Translates substitutions applicable in normal text, from a
defined list */
static bool translate_formatted_substitutions(input_cursor_ *const input, output_cursor_ *const output) {
	// All verbatim subsitutions are also applicable normally
	if (translate_verbatim_substitutions(input, output)) { return true; }

	static substitution_ const substitutions[] = {
		{ "\\\\", "\\" },
		{ "\\{", "{" },
		{ "\\}", "}" },
		{ "\\&", "&" },
		{ "--", "&ndash;" },
		{ "``", "&ldquo;" },
		{ "`", "&lsquo;" },
		{ "''", "&rdquo;" },
		{ "'", "&rsquo;" },
	};
	return translate_substitutions(input, output, COUNT(substitutions), substitutions);
}

/* Translates any character that would be a valid component of a word
in text. */
static bool translate_word_char(input_cursor_ *const input, output_cursor_ *const output) {
	// Formatted substitutions are allowed inside of words
	if (translate_formatted_substitutions(input, output)) { return true; }

	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	/* Anything that can be interpreted as a space is not a word
	character */
	if (translate_space(&my_input, &my_output)) { return false; }

	/* Parse a single actual character.  Anything other than the three
	special characters \ { } is acceptable. */
	char c;
	if (!parse_any_char(&my_input, &c)) { return false; }
	if (c == '\\' || c == '{' || c == '}') { return false; }
	generate_char(&my_output, c);

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates a single word of text */
static bool translate_word(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	// Get the length of the word by counting how many word characters can be scanned
	size_t i;
	for (i = 0;; ++i) {
		if (!translate_word_char(&my_input, &my_output)) { break; }
	}
	if (i == 0) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

/* The sequence "\ " (with a literal backslash) in the input text is a
special space character which correponds to an en-space (HTML "&ensp;").
This function translates this sequence. */
static bool translate_sentence_break(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '\\')) { return false; }

	/* We use "dummy" inputs and outputs here because the space should
	not actually be eaten input in the input: since "\n" counts as a
	space character, it might also need to be used afterward to parse
	"\n\n", which indicates a section break.  If the space were used
	up here, the break would not be detected.  If the space ends up not
	being used for that, it's fine that it is scanned again as a plain
	space, because of the `pending_space_` buffering. */
	input_cursor_ dummy_input = my_input;
	output_cursor_ dummy_output = my_output;
	if (!translate_space(&dummy_input, &dummy_output)) { return false; }
	ASSERT(dummy_output.pending_space == PENDING_SPACE_PLAIN);

	generate_pending_space(&my_output, PENDING_SPACE_EN);

	*input = my_input;
	*output = my_output;
	return true;
}

/* Identifies characters that are valid in the names of commands. */
static bool is_command_word_char(char const c) {
	if ('0' <= c && c <= '9') { return true; }
	if ('A' <= c && c <= 'Z') { return true; }
	if ('a' <= c && c <= 'z') { return true; }
	if (strchr("-_", c) != NULL) { return true; }
	return false;
}

/* Scans a single character that is allowed in the name of a command, at the position
indicated by the cursor, if it exists.  Returns `false` if it cannot be parsed. */
static bool translate_command_word_char(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	char c;
	if (!parse_any_char(&my_input, &c)) { return false; }
	if (!is_command_word_char(c)) { return false; }
	generate_char(&my_output, c);

	*input = my_input;
	*output = my_output;
	return true;
}

/* Scans a string of as many characters as possible allowed in the name
of a command, starting at the position indicated by the cursor.  Returns
`false` if not even the first character is part of a valid command name.
*/
static bool translate_command_word(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	size_t i;
	for (i = 0;; ++i) {
		if (!translate_command_word_char(&my_input, &my_output)) { break; }
	}
	if (i == 0) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

/* Parses an arbitrary string of text surrounded by square brackets
("[]"), and writes the string into the output. */
static bool translate_attributes(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '[')) { return false; }
	for (;;) {
		char c;
		if (!parse_any_char(&my_input, &c)) { return false; }
		if (c == ']') { break; }
		generate_char(&my_output, c);
	}

	*input = my_input;
	*output = my_output;
	return true;
}

/* Parses an arbitrary string of text surrounded by triple backticks
("```"), and writes the string into the output. */
static bool translate_verbatim(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_string(&my_input, "```")) { return false; }
	for (;;) {
		if (parse_string(&my_input, "```")) { break; }

		if (translate_verbatim_substitutions(&my_input, &my_output)) { continue; }

		char c;
		if (!parse_any_char(&my_input, &c)) { return false; }
		generate_char(&my_output, c);
	}

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_token(input_cursor_ *, output_cursor_ *);

/* Parses an arbitrary string of text surrounded by curly braces
("{}"), and writes the string into the output.  The string can
contain curly braces as long as they are matched.  A brace matching
the brace opening the block closes the block. */
static bool translate_verbatim_block(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '{')) { return false; }
	size_t depth = 1;
	for (;;) {
		if (translate_verbatim_substitutions(&my_input, &my_output)) { continue; }

		char c;
		if (!parse_any_char(&my_input, &c)) { return false; }
		if (c == '{') { ++depth; }
		if (c == '}') { --depth; }
		if (depth == 0) { break; }
		generate_char(&my_output, c);
	}

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translate a piece of text (which can contain more tokens that will be
parsed) surrounded by curly braces.  The curly braces are not written in
the output. */
static bool translate_block(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '{')) { return false; }
	for (;;) {
		if (!translate_token(&my_input, &my_output)) { break; }
	}
	if (!parse_char(&my_input, '}')) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates a command. */
static bool translate_command(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '\\')) { return false; }

	/* A grave character can be used to indicate that the block should
	be parsed verbatim. */
	bool const verbatim = parse_char(&my_input, '`');

	// Parse command name
	output_cursor_ *const word_output = create_output();
	bool const word = translate_command_word(&my_input, word_output);

	// Parse attributes
	output_cursor_ *const attributes_output = create_output();
	bool const attributes = translate_attributes(&my_input, attributes_output);

	// Parse a block
	output_cursor_ *const block_output = create_output();
	bool const block = (verbatim ? translate_verbatim_block : translate_block)(&my_input, block_output);

	/* Generate the output according to what components are and aren't
	present */
	if (word) {
		generate_char(&my_output, '<');
		generate_output(&my_output, word_output);
		if (attributes) {
			generate_char(&my_output, ' ');
			generate_output(&my_output, attributes_output);
		}
		if (block) {
			generate_char(&my_output, '>');
			generate_output(&my_output, block_output);
			generate_string(&my_output, "</");
			generate_output(&my_output, word_output);
			generate_char(&my_output, '>');
		} else {
			generate_string(&my_output, " />");
		}
	} else {
		generate_output(&my_output, block_output);
	}

	destroy_output(word_output);
	destroy_output(attributes_output);
	destroy_output(block_output);

	// The following configuations are illegal are should not parse
	if (!verbatim && !word) { return false; }
	if (!word && attributes) { return false; }
	if (verbatim && !block) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates a token (anything found in a section of text). */
static bool translate_token(input_cursor_ *const input, output_cursor_ *const output) {
	if (translate_verbatim(input, output)) { return true; }
	if (translate_word(input, output)) { return true; }
	if (translate_space(input, output)) { return true; }
	if (translate_sentence_break(input, output)) { return true; }
	if (translate_block(input, output)) { return true; }
	if (translate_command(input, output)) { return true; }
	return false;
}

/* Parses a section break: a sequence of two or more newline characters,
indicating a break between sections. */
static bool parse_section_break(input_cursor_ *const input) {
	input_cursor_ my_input = *input;

	size_t i;
	for (i = 0;; ++i) {
		// End of input counts as a section break
		if (parse_end(&my_input)) {
			i = SIZE_MAX;
			break;
		}
		if (!parse_char(&my_input, '\n')) { break; }
	}
	if (i < 2) { return false; }

	*input = my_input;
	return true;
}

/* Translates a token in a section, ensuring there is not a section
break that should be handled instead. */
static bool translate_section_token(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	if (parse_section_break(&my_input)) { return false; }
	return translate_token(input, output);
}

/* Translates the HTML attributes of a section command, in the same way
as `translate_attributes`. */
static bool translate_section_command_attributes(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	generate_char(&my_output, ' ');
	if (!translate_attributes(&my_input, &my_output)) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates a section command (a section consisting of a single HTML
tag that contains more elements or text inside). */
static bool translate_section_command(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	// Indicator for section commands
	if (!parse_string(&my_input, "\\.")) { return false; }
	if (!translate_command_word(&my_input, &my_output)) { return false; }
	translate_section_command_attributes(&my_input, &my_output);

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates a command section (a section consisting of a single HTML
tag, an empty element). */
static bool translate_command_section(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	// Indicator for command sections
	if (!parse_string(&my_input, "\\?")) { return false; }

	generate_char(&my_output, '<');
	if (!translate_command_word(&my_input, &my_output)) { return false; }
	translate_section_command_attributes(&my_input, &my_output);
	if (!parse_section_break(&my_input)) { return false; }
	generate_string(&my_output, " />\n");

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates an entire section, e.g. a paragraph */
static bool translate_section(input_cursor_ *const input, output_cursor_ *const output) {
	if (translate_command_section(input, output)) { return true; }

	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	// Handle section commands; otherwise use a `<p>` tag
	output_cursor_ *const section_command_output = create_output();
	if (!translate_section_command(&my_input, section_command_output)) {
		generate_char(section_command_output, 'p');
	}

	generate_char(&my_output, '<');
	generate_output(&my_output, section_command_output);
	generate_char(&my_output, '>');

	/* Spaces should never occur immediately before or after an HTML tag
	marking a section, since the tag name should denote a block element
	*/
	generate_pending_space(&my_output, PENDING_SPACE_BLOCKED);

	// Translate tokens until there are no more, then parse a section break
	for (;;) {
		if (!translate_section_token(&my_input, &my_output)) { break; }
	}
	if (!parse_section_break(&my_input)) {
		destroy_output(section_command_output);
		return false;
	}

	generate_pending_space(&my_output, PENDING_SPACE_BLOCKED);

	generate_string(&my_output, "</");
	generate_output(&my_output, section_command_output);
	generate_string(&my_output, ">\n");

	destroy_output(section_command_output);

	*input = my_input;
	*output = my_output;
	return true;
}

/* Translates the entire input, as many sections are there are.  Returns
`false` if the parse fails (because of a syntax error). */
static bool translate_texhtml(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_start(&my_input)) { return false; }
	for (;;) {
		// Once the end of the input is reached, we are done
		if (parse_end(&my_input)) { break; }

		if (!translate_section(&my_input, &my_output)) { return false; }
	}

	*input = my_input;
	*output = my_output;
	return true;
}

/* Gets the line number and character number in that line, for a given
input string and the position (number of bytes) into that string, by
counting line breaks. */
static void get_line_nr_char_nr(char const *const str, size_t const pos, size_t *const out_line_nr, size_t *const out_char_nr) {
	ASSERT(str != NULL && out_line_nr != NULL && out_char_nr != NULL);
	size_t line_nr = 0;
	size_t line_pos = 0;
	for (size_t i = 0; i < pos; ++i) {
		if (str[i] == '\n') {
			++line_nr;
			line_pos = i + 1;
		}
	}
	*out_line_nr = 1 + line_nr;
	*out_char_nr = 1 + pos - line_pos;
}

/* Performs a translation of the texhtml input file into the HTML
output.  Returns an output cursor, which contains a buffer and a
position indicating where the buffer ends.  If the input cannot be
parsed, writes an error message to stdout and terminates the program. */
static output_cursor_ *translate(size_t input_size, char const *const input_data) {
	input_ input = { 0, input_size, input_data };
	input_cursor_ input_cursor = { &input, 0 };

	output_cursor_ *const output = create_output();

	if (!translate_texhtml(&input_cursor, output)) {
		size_t line_nr, char_nr;
		get_line_nr_char_nr(input.data, input.max_parse, &line_nr, &char_nr);
		fprintf(stderr, "Syntax error near line %zu, char %zu\n", line_nr, char_nr);
		exit(EXIT_FAILURE);
	}

	return output;
}

int main(void) {
	// Read the file from stdin
	size_t input_size;
	char *const input = read_file(stdin, &input_size);
	ASSERT(input != NULL);

	// Translate it into HTML
	output_cursor_ *const output = translate(input_size, input);
	ASSERT(output != NULL);

	// Write the result to stdout
	if (output->position != 0) {
		fwrite(output->output->buffer, 1, output->position, stdout);
	}

	free(input);
	destroy_output(output);

	return EXIT_SUCCESS;
}
