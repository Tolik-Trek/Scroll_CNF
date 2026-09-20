/* Altera zero packer and depacker by Shaos (2017,2021) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv)
{
 int b,i,n;
 long l,maxzero,nonzero,nzero,sz,current=0;
 FILE *f,*fo;
 if(argc<3)
 {
    printf("\n\t%s imgfilename packedfilename\nor",argv[0]);
    printf("\n\t%s -d packedfilename depackedfile\n",argv[0]);
    return 0;
 }
 if(argv[1][0]=='-' && argv[1][1]=='d')
 {
    f = fopen(argv[2],"rb");
    if(f==NULL) return -1;
    if(argc==3) fo = fopen("Altera.bin","wb");
    else fo = fopen(argv[3],"wb");
    if(fo==NULL){fclose(f);return -2;}
    fseek(f,0,SEEK_END);
    sz = ftell(f);
    printf("Size=%li\n",sz);
    fseek(f,0,SEEK_SET);
    printf("Depack %s (size=%li)\n",argv[2],sz);
    for(l=0;l<sz;l++)
    {
       b = fgetc(f);
       if(b) fputc(b,fo);
       else
       {
          l++;
          n = fgetc(f);
          for(i=0;i<n;i++) fputc(0,fo);
       }
    }
    fclose(fo);
    fclose(f);
    return 0;
 }
 f = fopen(argv[1],"rb");
 if(f==NULL) return -1;
 fseek(f,0,SEEK_END);
 sz = ftell(f);
 printf("Size=%li\n",sz);
 fseek(f,0,SEEK_SET);
 fo = fopen(argv[2],"wb");
 if(fo==NULL){fclose(f);return -2;}
 maxzero = nonzero = current = nzero = 0;
 for(l=0;l<sz;l++)
 {
       b = fgetc(f);
       if(b || nzero==255)
       {
          if(nzero)
          {
             if(nzero>maxzero) maxzero=nzero;
             current+=2;
             fputc(0,fo);
             fputc(nzero,fo);
          }
          if(b)
          {
             nzero = 0;
             nonzero++;
             current++;
             fputc(b,fo);
          }
          else nzero = 1;
       }
       else nzero++;
 }
 if(nzero)
 {
       if(nzero>maxzero) maxzero=nzero;
       current+=2;
       fputc(0,fo);
       fputc(nzero,fo);
 }
 printf("maxzero=%li nonzero=%li current=%li\n",maxzero,nonzero,current);
 fclose(fo);
 fclose(f);
 return 0;
}
