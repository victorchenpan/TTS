LIB_DIR=./lib
ALL:gen_tts_lib.c
	gcc gen_tts_lib.c -L ${LIB_DIR} ./lib/libchar_conversion.a -o gen_tts
