// DexDrive dumping program
// initial version by paulguy
// added configuration via commandline by jsperling

// Some code copied from Serial Programming HOWTO by Gary Frerking and Peter Baumann
// http://tldp.org/HOWTO/Serial-Programming-HOWTO/

// Used DexDrive protocol documentation from linux-dexdrive module by Frédéric Brière
// http://www.gitorious.org/linux-dexdrive

// Some code copied from the GNU C Library documentation by the Free Software Foundation, Inc.
// https://www.gnu.org/software/libc/manual/html_node/Getopt.html

#define _POSIX_C_SOURCE (199309L)

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#define FALSE 0
#define TRUE 1
#define BARMAXSIZE 60

// Tidy stdint.h names
typedef uint8_t Uint8;
typedef int8_t Sint8;
typedef uint16_t Uint16;
typedef int16_t Sint16;
typedef uint32_t Uint32;
typedef int32_t Sint32;

typedef enum {
	INIT = 0x00,
	STATUS = 0x01,
	READ = 0x02,
	SEEK = 0x03,
	WRITE = 0x04,
	PAGE = 0x05,
	LIGHT = 0x07,
	MAGIC_HANDSHAKE = 0x27
} DDCommand;

typedef enum {
	POUT = 0x20,
	ERROR = 0x21,
	NOCARD = 0x22,
	CARD = 0x23,
	CARD_NEW = 0x25,
	SEEK_OK = 0x27,
	WRITE_OK = 0x28,
	WRITE_SAME = 0x29,
	WAIT = 0x2A,
	ID = 0x40,
	DATA = 0x41,
	FAIL = 0xFF
} DDResponse;

typedef enum {
	N64, PSX
} DDType;

void show_help(void);
void cleanup(int fd, struct termios oldtio, int status);
char *HexOut(const Uint8 *data, const Uint32 length);
char *DDStrResponse(DDResponse response);
DDResponse DDSendCmd(int fd, DDCommand cmd, const Uint8 *outdata, const Uint32 outlength, Uint8 *indata, Uint32 *inlength, Uint32 maxinlength);
DDResponse DDInit(int fd, Uint8 *data, Uint32 *datalen);
DDResponse DDStatus(int fd, Uint8 *data, Uint32 *datalen);
DDResponse DDHandshake(int fd);
DDResponse DDRead(int fd, Uint16 frame, Uint8 *data, Uint32 *datalen, Uint32 blocksize);
DDResponse DDLight(int fd, Uint8 light);

const Uint8 DD_PREFIX[] = { 0x49, 0x41, 0x49 }; // "IAI"
const Uint32 DD_PREFIX_LENGTH = 3;
const Uint8 DD_INIT_DATA[] = { 0x10, 0x29, 0x23, 0xBE, 0x84, 0xE1, 0x6C, 0xD6, 0xAE, 0x52, 0x90, 0x49, 0xF1, 0xF1, 0xBB, 0xE9, 0xEB }; // Magic Init Value
const Uint32 DD_INIT_DATA_LENGTH = 17;

int debug = FALSE;

int main(int argc, char **argv) {
	int fd;
  int count;
	int index;
	struct termios oldtio,newtio;
	Uint8 buffer[257];	// temporary buffer for reads, largest response is a DATA response from an N64 DexDrive
	Uint32 length;
	DDType type;		// detected type
	DDResponse response;
	char *tmp;
	Uint32 framesdump;	// frames to dump (size of card)
	Uint32 framesize;	// size of each frame
	Uint16 i, j;
	FILE *outfile;
	struct timespec wait;
	Uint32 barsize;		// current length of the progress bar
	Uint32 barstep;		// pages per each progress bar char
	char *animation;
	Uint32 animlength;

	char *serialport = "/dev/ttyUSB0";
	char *memcardfile ="memcard.mcr";
	int blinklight = FALSE;

	//animation = ".oOo. ";
	animation = "-\\|/";
	animlength = strlen(animation);

	while((count = getopt (argc, argv, "bdf:hs:")) != -1)
		switch(count) {
			case 'b':
				blinklight = TRUE;
				break;
			case 'd':
				debug = TRUE;
				break;
			case 'f':
				memcardfile = optarg;
				break;
			case 'h':
				show_help();
				exit(-1);
				break;
			case 's':
				serialport = optarg;
				break;
			case '?':
				if ((optopt == 'f')||(optopt == 'm'))
					fprintf(stderr, "Option '-%c' requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf(stderr, "Unknown option '-%c'.\n", optopt);
				else
				  fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
				exit(-1);
			default:
				abort();
		}		
     
	if (debug) {
		fprintf(stdout, "DEBUG: serialport = %s, memcardfile = %s, blinklight = %d, debug = %d\n",
			      				serialport, memcardfile, blinklight, debug);
	}
															     
	
	for (index = optind; index < argc; index++) {
		fprintf(stderr, "Non-option argument %s\n", argv[index]);
		exit(-1);
	}

	if (access(memcardfile, F_OK) == 0) {
		fprintf(stderr, "File %s already exist, aborting.\n", memcardfile);
		exit(-1);
	}

	fd = open(serialport, O_RDWR | O_NOCTTY ); 
	if (fd < 0) {
		perror(serialport);
		cleanup(fd, oldtio, -1);
	}

	tcgetattr(fd,&oldtio); /* save current port settings */

	bzero(&newtio, sizeof(newtio));
	newtio.c_cflag = B38400 | CS8 | CLOCAL | CREAD ; // 38400 baud 8 bits no parity 1 stop bit
	newtio.c_iflag = IGNPAR | IXON | IXOFF;
	newtio.c_oflag = 0;

	/* set input mode (non-canonical, no echo,...) */
	newtio.c_lflag = 0;
 
	newtio.c_cc[VTIME]    = 100;	//Some operations are slow so give the device
									//a lot of time to complete (10 seconds)
	newtio.c_cc[VMIN]     = 0;		//Get whatever is available by the timeout

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd,TCSANOW,&newtio);
	response = DDInit(fd, buffer, &length);
	if(response != ID) {
		tmp = DDStrResponse(response);
		fprintf(stderr, "Couldn't initialize device: %s.\n", tmp);
		free(tmp);
		cleanup(fd, oldtio, -1);
	}
	if(length != 5) {
		fprintf(stderr, "Device returned incomplete init response.\n");
		cleanup(fd, oldtio, -1);
	} else {
		tmp = HexOut(buffer, 5);
		fprintf(stdout, "Device initialized, returned %s\n", tmp);
		free(tmp);
		if(memcmp(&buffer[1], "PSX", 3) == 0) {
			fprintf(stdout, "Playstation DexDrive detected.\n");
			type = PSX;
			framesdump = 0x400;
			framesize = 128;
		} else if(memcmp(&buffer[1], "N64", 3) == 0) {
			fprintf(stdout, "Nintendo 64 DexDrive detected.\n");
			type = N64;
			framesdump = 0x80;
			framesize = 256;
		} else {
			fprintf(stderr, "Unknown DexDrive detected.\n");
			cleanup(fd, oldtio, -1);
		}
		barstep = framesdump / BARMAXSIZE;
	}
	response = DDHandshake(fd);
	if(response == ERROR) {
		if(type == PSX) {
			fprintf(stdout, "Handshake returned expected ERROR response for a Playstation dexdrive.\n");
		} else {
			fprintf(stderr, "N64 DexDrive returned ERROR in response to handshake.\n");
			cleanup(fd, oldtio, -1);
		}
	}
	response = DDStatus(fd, buffer, &length);
	fprintf(stdout, "%s.\n", DDStrResponse(response));
	switch(response) {
		case NOCARD:
			cleanup(fd, oldtio, -1);
			break;
		case CARD_NEW:
			break;
		case CARD:
			if(type == PSX && length == 1) {
				switch(buffer[0]) {
					case 0x00:
						fprintf(stdout, "Playstation DexDrive reports a successful write since last reset.\n");
						break;
					case 0x10:
						fprintf(stdout, "Playstation DexDrive reports no successful writes since last reset.\n");
						break;
					default:
						fprintf(stderr, "Playstation DexDrive returned an unknown status: %X.", buffer[0]);
						break;
				}
			}
			break;
		default:
			cleanup(fd, oldtio, -1);
			break;
	}
	outfile = fopen(memcardfile, "wb");
	if(outfile == NULL) {
		fprintf(stderr, "Couldn't open file for writing.\n");
		cleanup(fd, oldtio, -1);
	}
	wait.tv_sec = 0;
	wait.tv_nsec = 10000000;
	for(i = 0; i < framesdump; i++) {

		//print progress bar
		fputc('\r', stderr);
		fputc('|', stderr);
		barsize = i / barstep;
		for(j = 0; j < barsize; j++) {
			fputc('=', stderr);
		}
		for(j = 0; j < BARMAXSIZE - barsize; j++) {
			fputc('-', stderr);
		}
		fprintf(stderr, "| %c %i/%i", animation[i % animlength], i + 1, framesdump);

		if (debug) {
			fprintf(stdout, "\n");
		}

		if (blinklight) {
			response = DDLight(fd, 1);
		}

		response = DDRead(fd, i, buffer, &length, framesize + 1);
		if(length < framesize + 1) {
			fprintf(stderr, "Incomplete DATA response, expected %d bytes, got %d.\n", framesize + 1, length);
			if (blinklight) {
				response = DDLight(fd, 0);
			}
			cleanup(fd, oldtio, -1);
		}

		switch(response) {
			case NOCARD:
				fprintf(stderr, "No card is inserted or card removed.\n");
				if (blinklight) {
					response = DDLight(fd, 0);
				}
				cleanup(fd, oldtio, -1);
				break;
			case DATA:
				fwrite(buffer, sizeof(Uint8), framesize, outfile);
				break;
			default:
				tmp = DDStrResponse(response);
				fprintf(stderr, "Got an unexpected response: %s.\n", tmp);
				free(tmp);
				if (blinklight) {
					response = DDLight(fd, 0);
				}
				cleanup(fd, oldtio, -1);
				break;
		}

		if (blinklight) {
			response = DDLight(fd, 0);
		}

		nanosleep(&wait, NULL);
	}

	fclose(outfile);
	fprintf(stdout, "\nDump complete and saved as %s\n", memcardfile);
	cleanup(fd, oldtio, 0);
}

void show_help(void) {
	fprintf(stdout, "Usage:DDread [OPTIONS]\n"\
									"This programm will dump a memory card from a DexDrive.\n"\
									"Currently it only supports PSX and N64 DexDrives while the PSX DexDrive is tested best.\n\n"\
									"You can choose the follwing Options:\n"\
									"\t-b  enable the blinking light on the DexDrive, this will slow down the dump\n"\
									"\t-d  enable debug messages\n"\
									"\t-f  the file the memory card is saved to (Default \"memcard.mcr\")\n"\
									"\t-h  display this help text and exit\n"\
									"\t-s  choose the serial port the DexDrive is attached to (Default \"/dev/ttyUSB0\")\n");
}

void cleanup(int fd, struct termios oldtio, int status) {
	tcsetattr(fd,TCSANOW,&oldtio);
	exit(status);
}

char *HexOut(const Uint8 *data, const Uint32 length) {
	Uint32 i;
	char *out;

	out = (char *)malloc(sizeof(char) * 5 * length + 1);
	if(length != 0) {
		for(i = 0; i < length; i++) {
			if(data[i] > 0xF) {
				sprintf(&out[i * 5], "0x%X ", data[i]);
			} else {
				sprintf(&out[i * 5], "0x0%X ", data[i]);
			}
		}
		out[length * 5 - 1] = '\0';
	} else {
		out[0] = '\0';
	}

	return(out);
}

char *DDStrResponse(DDResponse response) {
	const char POUTstr[] = "POUT: Device is pouting";
	const char ERRORstr[] = "ERROR: Device returned an error";
	const char NOCARDstr[] = "NOCARD: No card is inserted";
	const char CARDstr[] = "CARD: A card is inserted";
	const char CARD_NEWstr[] = "CARD_NEW: A new card is inserted";
	const char SEEK_OKstr[] = "SEEK_OK: Seek position updated";
	const char WRITE_OKstr[] = "WRITE_OK: Frame successfully written";
	const char WRITE_SAMEstr[] = "WRITE_SAME: Write change will have no effect (new data is the same as old data)";
	const char WAITstr[] = "WAIT: Device is working";
	const char IDstr[] = "ID: Identification data follows";
	const char DATAstr[] = "DATA: Data follows";
	const char FAILstr[] = "Other failure detected";
	const char unknown[] = "Unknown response code: ";

	char *tmp;

	switch(response) {
		case POUT:
			tmp = (char *)malloc(sizeof(char) * (strlen(POUTstr) + 1));
			sprintf(tmp, "%s", POUTstr);
			return(tmp);
			break;
		case ERROR:
			tmp = (char *)malloc(sizeof(char) * (strlen(ERRORstr) + 1));
			sprintf(tmp, "%s", ERRORstr);
			return(tmp);
			break;
		case NOCARD:
			tmp = (char *)malloc(sizeof(char) * (strlen(NOCARDstr) + 1));
			sprintf(tmp, "%s", NOCARDstr);
			return(tmp);
			break;
		case CARD:
			tmp = (char *)malloc(sizeof(char) * (strlen(CARDstr) + 1));
			sprintf(tmp, "%s", CARDstr);
			return(tmp);
			break;
		case CARD_NEW:
			tmp = (char *)malloc(sizeof(char) * (strlen(CARD_NEWstr) + 1));
			sprintf(tmp, "%s", CARD_NEWstr);
			return(tmp);
			break;
		case SEEK_OK:
			tmp = (char *)malloc(sizeof(char) * (strlen(SEEK_OKstr) + 1));
			sprintf(tmp, "%s", SEEK_OKstr);
			return(tmp);
			break;
		case WRITE_OK:
			tmp = (char *)malloc(sizeof(char) * (strlen(WRITE_OKstr) + 1));
			sprintf(tmp, "%s", WRITE_OKstr);
			return(tmp);
			break;
		case WRITE_SAME:
			tmp = (char *)malloc(sizeof(char) * (strlen(WRITE_SAMEstr) + 1));
			sprintf(tmp, "%s", WRITE_SAMEstr);
			return(tmp);
			break;
		case WAIT:
			tmp = (char *)malloc(sizeof(char) * (strlen(WAITstr) + 1));
			sprintf(tmp, "%s", WAITstr);
			return(tmp);
			break;
		case ID:
			tmp = (char *)malloc(sizeof(char) * (strlen(IDstr) + 1));
			sprintf(tmp, "%s", IDstr);
			return(tmp);
			break;
		case DATA:
			tmp = (char *)malloc(sizeof(char) * (strlen(DATAstr) + 1));
			sprintf(tmp, "%s", DATAstr);
			return(tmp);
			break;
		case FAIL:
			tmp = (char *)malloc(sizeof(char) * (strlen(FAILstr) + 1));
			sprintf(tmp, "%s", FAILstr);
			return(tmp);
			break;
		default:
			tmp = (char *)malloc(sizeof(char) * (strlen(unknown) + 5));
			sprintf(tmp, "%s0x%X", unknown, response & 0xFF);
			return(tmp);
			break;
	}
}

DDResponse DDSendCmd(int fd, DDCommand cmd, const Uint8 *outdata, const Uint32 outlength, Uint8 *indata, Uint32 *inlength, Uint32 maxinlength) {
	DDResponse response;
	Uint32 length;
	Uint8 *prefix;
	char *tmp1, *tmp2;
	struct timespec wait;

	response = 0;
	cmd &= 0xFF;

	if (debug) {
		tmp1 = HexOut(DD_PREFIX, DD_PREFIX_LENGTH);
		tmp2 = HexOut(outdata, outlength);
		fprintf(stdout, "DEBUG: device <-- %s 0x%X %s\n", tmp1, cmd, tmp2);
		free(tmp1);
		free(tmp2);
	}

	write(fd, DD_PREFIX, DD_PREFIX_LENGTH);
	write(fd, &cmd, 1);
	if(outdata != NULL && outlength != 0) {
		write(fd, outdata, outlength);
	}

	wait.tv_sec = 0;
	switch(cmd) {
		case READ:
			wait.tv_nsec = 50000000;
			break;
		default:
			wait.tv_nsec = 35000000;
			break;
	}
	
	nanosleep(&wait, NULL);

	prefix = (Uint8 *)malloc(sizeof(Uint8) * 3);
	length = read(fd, prefix, 3);

	if (debug) {
		tmp1 = HexOut(prefix, length);
		fprintf(stdout, "DEBUG: device --> %s", tmp1);
		free(tmp1);
	}

	if(length < 3) {
		perror("read");
		return(FAIL);
	}
	if(memcmp(prefix, DD_PREFIX, DD_PREFIX_LENGTH) != 0) {
		return(FAIL);
	}
	free(prefix);

	response = 0;
	length = read(fd, &response, 1);
	if(length < 1) {
		return(FAIL);
	}

	if (debug) {
		fprintf(stdout, " 0x%X", response);
	}

	switch(response) {
		case CARD:
		case ID:
		case DATA:
			if(indata != NULL && maxinlength != 0) {
				length = read(fd, indata, maxinlength);

				if (debug) {
					tmp1 = HexOut(indata, length);
					fprintf(stdout, " %s", tmp1);
					free(tmp1);
				}

				if(inlength != NULL) {
					*inlength = length;
				}
			}
			break;
		default:
			break;
	}

	if (debug) {
		fprintf(stdout, "\n");
	}

	return(response);
}

DDResponse DDInit(int fd, Uint8 *data, Uint32 *datalen) {
	return(DDSendCmd(fd, INIT, DD_INIT_DATA, DD_INIT_DATA_LENGTH, data, datalen, 5));
}

DDResponse DDStatus(int fd, Uint8 *data, Uint32 *datalen) {
	return(DDSendCmd(fd, STATUS, NULL, 0, data, datalen, 1));
}

DDResponse DDHandshake(int fd) {
	return(DDSendCmd(fd, MAGIC_HANDSHAKE, NULL, 0, NULL, NULL, 0));
}

DDResponse DDRead(int fd, Uint16 frame, Uint8 *data, Uint32 *datalen, Uint32 blocksize) {
	Uint8 tmp[2];
	tmp[1] = frame >> 8;
	tmp[0] = frame & 0xFF;
	return(DDSendCmd(fd, READ, tmp, 2, data, datalen, blocksize));
}

DDResponse DDLight(int fd, Uint8 light) {
	return(DDSendCmd(fd, LIGHT, &light, 1, NULL, NULL, 0));
}
