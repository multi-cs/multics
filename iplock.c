//uint32_t datacrc = crc32(0L, buf+20, len-20);

uint8_t Lookup_Table[0x40] = {
  0x25,0x38,0xD4,0xCD,0x17,0x7A,0x5E,0x6C,0x52,0x42,0xFE,0x68,0xAB,0x3F,0xF7,0xBE,
  0x47,0x57,0x71,0xB0,0x23,0xC1,0x26,0x6C,0x41,0xCE,0x94,0x37,0x45,0x04,0xA2,0xEA,
  0x07,0x58,0x35,0x55,0x08,0x2A,0x0F,0xE7,0xAC,0x76,0xF0,0xC1,0xE6,0x09,0x10,0xDD,
  0xC5,0x8D,0x2E,0xD9,0x03,0x9C,0x3D,0x2C,0x4D,0x41,0x0C,0x5E,0xDE,0xE4,0x90,0xAE
  };

int pass_encrypt( unsigned char *buffer, unsigned char *pass )
{
  int passcounter;
  int bufcounter;
  unsigned char temp;

  for(passcounter=0; passcounter<4; passcounter++)
    for(bufcounter=7; bufcounter>=0; bufcounter--)
    {
      temp = ( buffer[bufcounter]>>2);
      temp = pass[3];
      pass[3] = (pass[3]/2)+(pass[2]&1)*0x80;
      pass[2] = (pass[2]/2)+(pass[1]&1)*0x80;
      pass[1] = (pass[1]/2)+(pass[0]&1)*0x80;
      pass[0] = (pass[0]/2)+(temp   &1)*0x80;
      buffer[(bufcounter+1) & 7] = buffer[ (bufcounter+1) & 7 ] - Lookup_Table[ (buffer[bufcounter]>>2) & 0x3F ];
      buffer[(bufcounter+1) & 7] = Lookup_Table[ ( buffer[bufcounter] - pass[(bufcounter+1) & 3] ) & 0x3F ] ^ buffer[ (bufcounter+1) & 7 ];
      buffer[(bufcounter+1) & 7] = buffer[ (bufcounter+1) & 7 ] - pass[(bufcounter & 3)];
    }
  
}

void pass_decrypt(unsigned char *buffer,unsigned char *pass)
{
 unsigned char temp;
 int bufcounter;
 int passcounter;
  for( passcounter=3; passcounter>=0; passcounter--) 
  for( bufcounter=0; bufcounter<=7; bufcounter++) {
    buffer[(bufcounter+1)&7] = pass[bufcounter&3] + buffer[(bufcounter+1)&7];
    temp = buffer[bufcounter] -  pass[(bufcounter+1)&3];
    buffer[(bufcounter+1)&7] = Lookup_Table[temp &0x3F] ^ buffer[(bufcounter+1)&7];
    temp = buffer[bufcounter] >> 2;
    buffer[(bufcounter+1)&7] =  Lookup_Table[temp & 0x3F] + buffer[(bufcounter+1)&7];

    temp = pass[0] & 0x80;
    pass[0] = ( (pass[1]&0x80)>>7 ) + (pass[0]<<1);
    pass[1] = ( (pass[2]&0x80)>>7 ) + (pass[1]<<1);
    pass[2] = ( (pass[3]&0x80)>>7 ) + (pass[2]<<1);
    pass[3] = ( temp>>7 ) + (pass[3]<<1);
  }

}

void message_decrypt(unsigned char *buffer, int bufsize, uint8_t *pass)
{
  int counter;
  pass_encrypt( &buffer[bufsize-9], pass);
  pass_decrypt( buffer, pass );
  for (counter=bufsize-2; counter>=0; counter--)
    buffer[counter] = buffer[counter+1] ^ buffer[counter];
}

int message_encrypt( unsigned char *buffer, int bufsize, uint8_t *pass)
{
 int counter;
  for (counter=0; counter<(bufsize-1); counter++)
    buffer[counter] = buffer[counter+1] ^ buffer[counter];
  pass_encrypt( buffer, pass );
  pass_decrypt( &buffer[bufsize-9], pass );
  return bufsize;
}

