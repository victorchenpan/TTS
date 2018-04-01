/*********************************************
*	以小端模式填充到语音库当中
* 使用方法： ./a.out ./wav
*********************************************/
#include <stdio.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include "char_conversion.h"

#define 	ALLOC_MEM_BUF_SIZE 	(450*1024)
#define   TTS_LIB_NAME 	"tts.bin"
#define   BIG_TO_LITTLE_ENDIAN_32(value)	((value&0x000000ff)<<24|(value&0x0000ff00)<<8|(value&0xff000000)>>24|(value&0x00ff0000)>>8)

typedef struct {
  uint8_t   magic[4];
  uint32_t  total;        //  how much word do we support
  uint32_t  baseAddr;     //  base address of TTS data
  uint32_t  mapSize;
  uint32_t  dataSize;     //  TTS data size
}TTS_FILE_HEADER_T;

typedef struct {
  uint8_t   unicode[2];
  uint16_t  dataSize;
  uint32_t  baseAddr;
}TTS_MAP_T;

static TTS_FILE_HEADER_T s_file_header = {
	.magic = "TTS",
	.total = 0,
	.baseAddr = sizeof(TTS_FILE_HEADER_T)+sizeof(TTS_MAP_T)*0,
	.mapSize = sizeof(TTS_MAP_T),
	.dataSize = 0,
};

static uint8_t	*s_mem_p = NULL;
static uint32_t	s_map_cur_p = 0;
static uint32_t s_data_cur_p = 0;
static uint32_t s_cur_progress = 0;

static uint32_t get_total_count_of_file(const char *dirname)
{
  uint32_t file_count = 0;
  struct dirent *ep = NULL;
  DIR *dp = NULL;

  if (!dirname) {
    printf("dirname is empty!\n");
    return 0;
  }

  dp = opendir(dirname);
  if (!dp) {
    printf("%s[%d]: errno = %d\n", __func__, __LINE__, errno);
    return 0;
  }

  while(ep = readdir(dp)) {
    if (ep->d_type == DT_DIR)
      continue;
    file_count++;
  }

  (void)closedir(dp);
  return file_count;
}

static int init_objects(const char *dirname)
{
  s_file_header.total = get_total_count_of_file(dirname);
  s_map_cur_p = sizeof(TTS_FILE_HEADER_T);
  s_data_cur_p = sizeof(TTS_FILE_HEADER_T) + sizeof(TTS_MAP_T)*s_file_header.total;
  return 0;
}

static char is_little_endian(void)
{
	int i = 1;
	return *(char*)(&i);
}

static void hexdump(const char *funcname, const void *data, unsigned int len)
{
	char str[160], octet[10];
	int ofs, i, k, d;
	const unsigned char *buf = (const unsigned char *)data;
	const char dimm[] = "+------------------------------------------------------------------------------+";
    char fname[sizeof(dimm)];
    unsigned int flen;

    flen = strlen(funcname);
    if (flen >= sizeof(fname) - 3) {
        printf("+%s+\r\n", &funcname[flen-sizeof(fname)-2]);
    } else {
        strcpy(fname, dimm);
        memcpy(&fname[(sizeof(fname) - 1 - flen)/2], funcname, flen);
    }

    printf("%s\r\n", fname);
    printf("| Offset  : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   0123456789ABCDEF |\r\n");
    printf("%s\r\n", dimm);

	for (ofs = 0; ofs < (int)len; ofs += 16) {
		d = snprintf( str, sizeof(str), "| %08x: ", ofs );

		for (i = 0; i < 16; i++) {
			if ((i + ofs) < (int)len)
				snprintf( octet, sizeof(octet), "%02x ", buf[ofs + i] );
			else
				snprintf( octet, sizeof(octet), "   " );

			d += snprintf( &str[d], sizeof(str) - d, "%s", octet );
		}
		d += snprintf( &str[d], sizeof(str) - d, "  " );
		k = d;

		for (i = 0; i < 16; i++) {
			if ((i + ofs) < (int)len)
				str[k++] = (0x20 <= (buf[ofs + i]) &&  (buf[ofs + i]) <= 0x7E) ? buf[ofs + i] : '.';
			else
				str[k++] = ' ';
		}

		str[k] = '\0';
		printf("%s |\r\n", str);
	}

    printf("%s\r\n", dimm);
}

static void tts_map_obj_init(TTS_MAP_T* obj, uint32_t size, const char* unicode)
{
  hexdump("UNICODE", unicode, 2);
	memcpy(obj->unicode, unicode, 2);
	obj->dataSize = (uint16_t)size;
	obj->baseAddr = s_data_cur_p;
}

static int tts_flush_header_to_file(FILE* fd, void *header_ptr)
{
	int retval = 0;
	int length = 0;

	if (!fd || !header_ptr) {
		retval = -1;
		goto exit_entry;
	}

	memcpy(&s_mem_p[0], header_ptr, sizeof(TTS_FILE_HEADER_T));
exit_entry:

	return retval;
}

static int tts_flush_map_to_file(FILE* fd, TTS_MAP_T* obj)
{
	int retval = 0;
	int write_len = 0;

	memcpy(&s_mem_p[s_map_cur_p], obj, sizeof(TTS_MAP_T));

	return 0;
}

static int tts_flush_data_to_file(FILE* fd, void *data, TTS_MAP_T* obj)
{
	int retval = 0;
	int write_len = 0;

	if (ALLOC_MEM_BUF_SIZE < (obj->baseAddr + obj->dataSize)) {
		perror("Out Of Memory\n");
		return -1;
	}

	memcpy(&s_mem_p[obj->baseAddr], data, obj->dataSize);
	return 0;
}

int tts_flush_wav_to_file(FILE* fd, const char* fname_in)
{
	int retval = 0;
	uint32_t	file_len = 0;
	uint8_t buf[10*1024] = {0,};
	FILE* fd_in = NULL;
	TTS_MAP_T	wav_map;
  char unicode[2] = {0,};

	fd_in = fopen(fname_in, "r");
	if (!fd_in) {
		retval = -1;
		printf("open %s ERROR,errno=%d\n", fname_in, errno);
		goto exit_entry;
	}

	file_len = fread(&buf, sizeof(uint8_t), sizeof(buf), fd_in);
	//printf("File Len:%d\n", file_len);
	//hexdump("file content", &buf, file_len);
  retval = utf8ToUnicode ((unsigned char*)&fname_in[6], (unsigned short *)unicode, sizeof(unicode));

	tts_map_obj_init(&wav_map, file_len, unicode);

	retval = tts_flush_map_to_file(fd, &wav_map);
	if (retval) {
		goto exit_entry;
	}

	retval = tts_flush_data_to_file(fd, &buf, &wav_map);
	if (retval) {
		goto exit_entry;
	}

	s_map_cur_p += sizeof(TTS_MAP_T);
	s_data_cur_p += file_len;
	s_cur_progress++;
	s_file_header.dataSize += file_len;

exit_entry:
	if (fd_in)
		fclose(fd_in);
	return retval;
}

int main(int argc, const char **argv)
{
	int retval = 0;
	DIR* dp = NULL;
	struct dirent *ep = NULL;
	FILE* out_file = NULL;
	char wav_name[30] = {0,};

  if (argc != 2) {
      printf("====> usage: ./gen_tts ./wav\n");
      printf("             ./wav :the dir of wav files\n");
      return -EINVAL;
  }

  init_objects(argv[1]);

	s_mem_p = (uint8_t*)malloc(ALLOC_MEM_BUF_SIZE);
	if (!s_mem_p) {
		retval = -4;
		printf("malloc error\n");
		goto exit_entry;
	}

	out_file = fopen(TTS_LIB_NAME, "ab+");
	if (out_file == NULL) {
		retval = -1;
		printf("open tts_res.bin ERROR\n");
		goto exit_entry;
	}

	dp = opendir(argv[1]);
	if (dp == NULL) {
		retval = -2;
		printf("opendir ERROR\n");
		goto exit_entry;
	}

	while (ep = readdir(dp)) {
		if (ep->d_type == DT_DIR) {
			continue;
		}
		puts(ep->d_name);
		//写入WAV文件到TTS语音库中
		memset(&wav_name, 0,sizeof(wav_name));
		memcpy(&wav_name[0], "./wav/", 6);
		memcpy(&wav_name[6], ep->d_name, strlen(ep->d_name));
		retval = tts_flush_wav_to_file(out_file, wav_name);
	}

	retval = tts_flush_header_to_file(out_file, &s_file_header);
	if (retval) {
		retval = -3;
		printf("flush header to file ERROR\n");
		goto exit_entry;
	}

		fwrite(s_mem_p, 1, s_file_header.dataSize + sizeof(TTS_MAP_T)*s_file_header.total + sizeof(s_file_header), out_file);
		fflush(out_file);

exit_entry:
	if (dp)
		(void)closedir(dp);
	if (out_file)
		fclose(out_file);

	return retval;
}
