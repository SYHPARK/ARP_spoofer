#include "getmacip.h"

int main() {
	char* ip = "192.168.43.97";
	char* myMac = getMyMac(ip);
	printf("%s", myMac);
}