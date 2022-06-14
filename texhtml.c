#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COUNT(...) (sizeof(__VA_ARGS__) / sizeof((__VA_ARGS__)[0]))

#ifdef DEBUG
#define ASSERT(COND) ((void)({ if (!(COND)) { __builtin_unreachable(); } }))
#else
#define ASSERT(COND) ((void)({ false && (COND); }))
#endif

typedef struct {
	size_t max_parse;
	size_t size;
	char const *data;
} input_;

typedef struct {
	input_ *input;
	size_t position;
} input_cursor_;

typedef struct {
	size_t capacity;
	char *buffer;
} output_;

typedef enum {
	PENDING_SPACE_NONE,
	PENDING_SPACE_PLAIN,
	PENDING_SPACE_EN,
	PENDING_SPACE_BLOCKED,
} pending_space_;

typedef struct {
	output_ *output;
	size_t position;
	pending_space_ pending_space;
} output_cursor_;

typedef struct {
	char const *in;
	char const *out;
} substitution_;

static void *xrealloc(void *const old_ptr, size_t const size) {
	void *const ptr = realloc(old_ptr, size);
	if (ptr == NULL) {
		perror("realloc");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

static char *read_file(FILE *const fp, size_t *const out_size) {
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

static output_cursor_ *create_output(void) {
	output_ *const output = xrealloc(NULL, sizeof(*output));
	output_cursor_ *const cursor = xrealloc(NULL, sizeof(*cursor));
	*output = (output_){ 0, NULL };
	*cursor = (output_cursor_){ output, 0, PENDING_SPACE_NONE };
	return cursor;
}

static void destroy_output(output_cursor_ *const output) {
	free(output->output->buffer);
	free(output->output);
	free(output);
}

static bool parse_start(input_cursor_ *const input) {
	return input->position == 0;
}

static bool parse_end(input_cursor_ *const input) {
	return input->position == input->input->size;
}

static bool parse_any_char(input_cursor_ *const input, char *const c) {
	input_cursor_ my_input = *input;

	if (parse_end(&my_input)) { return false; }
	*c = my_input.input->data[my_input.position];
	my_input.input->max_parse = my_input.position;
	++my_input.position;

	*input = my_input;
	return true;
}

static bool parse_char(input_cursor_ *const input, char const c) {
	input_cursor_ my_input = *input;

	char res;
	if (!parse_any_char(&my_input, &res)) { return false; }
	if (res != c) { return false; }

	*input = my_input;
	return true;
}


static bool parse_string(input_cursor_ *const input, char const *const string) {
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

static void generate(output_cursor_ *const output, size_t const data_size, char const *const data) {
	output_cursor_ my_output = *output;
	generate_pending_space(&my_output, PENDING_SPACE_NONE);
	switch (output->pending_space) {
	case PENDING_SPACE_PLAIN:
		generate_char(&my_output, ' ');
		break;
	case PENDING_SPACE_EN:
		generate_string(&my_output, "&ensp;");
		break;
	default:
		break;
	}
	*output = my_output;

	if (data_size == 0) { return; }

	size_t const output_size = output->position + data_size;
	size_t const new_capacity = 2 * output_size;
	if (output_size < data_size || new_capacity < output_size) {
		fprintf(stderr, "Output is too large");
		exit(EXIT_FAILURE);
	}
	if (output_size > output->output->capacity) {
		output->output->buffer = xrealloc(output->output->buffer, new_capacity);
		output->output->capacity = new_capacity;
	}
	memcpy(&output->output->buffer[output->position], data, data_size);
	output->position = output_size;
}

static void generate_char(output_cursor_ *const output, char const c) {
	generate(output, 1, &c);
}

static void generate_pending_space(output_cursor_ *const output, pending_space_ const pending_space) {
	if (pending_space == PENDING_SPACE_NONE || output->pending_space < pending_space) {
		output->pending_space = pending_space;
	}
}

static void generate_string(output_cursor_ *const output, char const *const string) {
	generate(output, strlen(string), string);
}

static void generate_output(output_cursor_ *const output, output_cursor_ *const src) {
	generate(output, src->position, src->output->buffer);
}

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

static bool translate_substitutions(input_cursor_ *const input, output_cursor_ *const output, size_t const substitution_count, substitution_ const *const substitutions) {
	for (size_t i = 0; i < substitution_count; ++i) {
		substitution_ const subst = substitutions[i];

		input_cursor_ my_input = *input;
		output_cursor_ my_output = *output;

		if (parse_string(&my_input, subst.in)) {
			generate_string(&my_output, subst.out);

			*input = my_input;
			*output = my_output;
			return true;
		}
	}
	return false;
}

static bool translate_verbatim_substitutions(input_cursor_ *const input, output_cursor_ *const output) {
	static substitution_ const substitutions[] = {
		{ "&", "&amp;" },
		{ "<", "&lt;" },
		{ ">", "&gt;" },
	};
	return translate_substitutions(input, output, COUNT(substitutions), substitutions);
}

static bool translate_formatted_substitutions(input_cursor_ *const input, output_cursor_ *const output) {
	if (translate_verbatim_substitutions(input, output)) { return true; }

	static substitution_ const substitutions[] = {
		{ "\\\\", "\\" },
		{ "\\{", "{" },
		{ "\\}", "}" },
		{ "\\&", "&" },
		{ "--", "&endash;" },
		{ "``", "&ldquo;" },
		{ "`", "&lsquo;" },
		{ "''", "&rdquo;" },
		{ "'", "&rsquo;" },
	};
	return translate_substitutions(input, output, COUNT(substitutions), substitutions);
}

static bool translate_word_char(input_cursor_ *const input, output_cursor_ *const output) {
	if (translate_formatted_substitutions(input, output)) { return true; }

	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (translate_space(&my_input, &my_output)) { return false; }

	char c;
	if (!parse_any_char(&my_input, &c)) { return false; }
	if (strchr("\\{}", c) != NULL) { return false; }
	generate_char(&my_output, c);

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_word(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	size_t i;
	for (i = 0;; ++i) {
		if (!translate_word_char(&my_input, &my_output)) { break; }
	}
	if (i == 0) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_sentence_break(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '\\')) { return false; }

	input_cursor_ dummy_input = my_input;
	output_cursor_ dummy_output = my_output;
	if (!translate_space(&dummy_input, &dummy_output)) { return false; }

	generate_pending_space(&my_output, PENDING_SPACE_EN);

	*input = my_input;
	*output = my_output;
	return true;
}

static bool is_command_word_char(char const c) {
	if ('0' <= c && c <= '9') { return true; }
	if ('A' <= c && c <= 'Z') { return true; }
	if ('a' <= c && c <= 'z') { return true; }
	if (strchr("-_", c) != NULL) { return true; }
	return false;
}

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

static bool translate_verbatim(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_string(&my_input, "```")) { return false; }
	for (;;) {
		if (parse_string(&my_input, "```")) { break; }

		char c;
		if (!parse_any_char(&my_input, &c)) { return false; }
		generate_char(&my_output, c);
	}

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_token(input_cursor_ *, output_cursor_ *);

static bool translate_verbatim_block(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '{')) { return false; }
	size_t depth = 1;
	for (;;) {
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

static bool translate_command(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_char(&my_input, '\\')) { return false; }
	bool const verbatim = parse_char(&my_input, '`');

	output_cursor_ *const word_output = create_output();
	bool const word = translate_command_word(&my_input, word_output);

	output_cursor_ *const attributes_output = create_output();
	bool const attributes = translate_attributes(&my_input, attributes_output);

	output_cursor_ *const block_output = create_output();
	bool const block = (verbatim ? translate_verbatim_block : translate_block)(&my_input, block_output);

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

	if (!verbatim && !word) { return false; }
	if (!word && attributes) { return false; }
	if (verbatim && !block) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_token(input_cursor_ *const input, output_cursor_ *const output) {
	if (translate_verbatim(input, output)) { return true; }
	if (translate_word(input, output)) { return true; }
	if (translate_space(input, output)) { return true; }
	if (translate_sentence_break(input, output)) { return true; }
	if (translate_block(input, output)) { return true; }
	if (translate_command(input, output)) { return true; }
	return false;
}

static bool parse_section_break(input_cursor_ *const input) {
	input_cursor_ my_input = *input;

	size_t i;
	for (i = 0;; ++i) {
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

static bool translate_section_token(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	if (parse_section_break(&my_input)) { return false; }
	return translate_token(input, output);
}

static bool translate_section_command_attributes(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	generate_char(&my_output, ' ');
	if (!translate_attributes(&my_input, &my_output)) { return false; }

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_section_command(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_string(&my_input, "\\.")) { return false; }
	if (!translate_command_word(&my_input, &my_output)) { return false; }
	translate_section_command_attributes(&my_input, &my_output);

	*input = my_input;
	*output = my_output;
	return true;
}

static bool translate_command_section(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

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

static bool translate_section(input_cursor_ *const input, output_cursor_ *const output) {
	if (translate_command_section(input, output)) { return true; }

	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	output_cursor_ *const section_command_output = create_output();
	if (!translate_section_command(&my_input, section_command_output)) {
		generate_char(section_command_output, 'p');
	}

	generate_char(&my_output, '<');
	generate_output(&my_output, section_command_output);
	generate_char(&my_output, '>');
	generate_pending_space(&my_output, PENDING_SPACE_BLOCKED);
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

static bool translate_sentence(input_cursor_ *const input, output_cursor_ *const output) {
	input_cursor_ my_input = *input;
	output_cursor_ my_output = *output;

	if (!parse_start(&my_input)) { return false; }
	for (;;) {
		if (parse_end(&my_input)) { break; }
		if (!translate_section(&my_input, &my_output)) { return false; }
	}

	*input = my_input;
	*output = my_output;
	return true;
}

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

static output_cursor_ *translate(size_t input_size, char const *const input_data) {
	input_ input = { 0, input_size, input_data };
	input_cursor_ input_cursor = { &input, 0 };

	output_cursor_ *const output = create_output();

	if (!translate_sentence(&input_cursor, output)) {
		size_t line_nr, char_nr;
		get_line_nr_char_nr(input.data, input.max_parse, &line_nr, &char_nr);
		fprintf(stderr, "Syntax error near line %zu, char %zu\n", line_nr, char_nr);
		exit(EXIT_FAILURE);
	}

	return output;
}

int main(void) {
	size_t input_size;
	char *const input = read_file(stdin, &input_size);

	output_cursor_ *const output = translate(input_size, input);

	if (output->position != 0) {
		fwrite(output->output->buffer, 1, output->position, stdout);
	}

	free(input);
	destroy_output(output);

	return EXIT_SUCCESS;
}
