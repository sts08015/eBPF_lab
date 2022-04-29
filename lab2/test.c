#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define BUF_LEN 1024
char buf[BUF_LEN];

int main(void)
{
    sleep(30);

    int fd = open("/mnt/lab/test",O_CREAT | O_RDWR);
    
    ssize_t ret;
    int len = lseek(fd,0,SEEK_END); //file size
    if(len<0){
        perror("why?");
        return -1;
    }
    printf("FILESIZE : %d\n",len);

    lseek(fd,0,SEEK_SET);

    while(lseek(fd,0,SEEK_CUR) < len)
    {
        ret = read(fd,buf,BUFSIZ);
    }

    close(fd);
    return 0;
}