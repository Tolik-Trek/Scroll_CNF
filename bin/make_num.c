#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
 FILE *f;
 unsigned int l,sz,bb,ll;
 unsigned short b[4];
 f = fopen(argv[1],"rb");
 if(f==NULL) return -1;
 fseek(f,0,SEEK_END);
 sz = ftell(f);
 fseek(f,0,SEEK_SET);
 printf("SIZE: %u\n",sz);
 b[0] = b[1] = b[2] = b[3] = 0;
 for(l=0;l<sz;l++)
 {
    bb = fgetc(f);
    b[0] += bb;
    if(b[0] >= 0x100)
    {
       b[0] &= 0xFF;
       b[1] += bb;
       if(b[1] >= 0x100)
       {
          b[1] &= 0xFF;
          b[2] += bb;
          if(b[2] >= 0x100)
          {
             b[2] &= 0xFF;
             b[3] += bb;
             if(b[3] >= 0x100)
                b[3] &= 0xFF;
          }
       }
    }
 }
 fclose(f);
 printf("SUM: %2.2X %2.2X %2.2X %2.2X\n",b[0],b[1],b[2],b[3]);
 return 0;
}
