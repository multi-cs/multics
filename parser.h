
extern char *iparser; // Current Parser Index

char *uppercase(char *str);

void parse_spaces();
int parse_value(char *str, char *delimiters);
int parse_str(char *str);
int parse_name(char *str);
int parse_boolean();
int parse_int(char *str);
int parse_hex(char *str);
int parse_bin(char *str);
int parse_expect( char c );
int parse_quotes( char quote, char *str );

