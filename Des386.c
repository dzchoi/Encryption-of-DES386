/*
    DES386 : DES algorithm for 80386+

    V 0.92, 99-11-14, dzchoi

    0.9	    changed the return type of member functions from des& to void
    0.91    fixed bugs in naked functions
	    (ebx should be preserved explicitly in naked functions)
    0.92    now working with real files
*/

/*
  TODO:
  1. decryption associated with ifstream and encryption associated with
     ofstream, or both associated with streambuf?
  2. MD5 algorithm?
  3. other applications of DES (e.g., cryptogram, ...)
*/



#define ARG(n)	dword ptr [esp+4*(n)] // for using in naked functions

#define PERM_OP(a, b, s, m)	\
    __asm   mov	    eax, a	\
    __asm   rol	    b, s	\
    __asm   xor	    eax, b	\
    __asm   and	    eax, m	\
    __asm   xor	    a, eax	\
    __asm   xor	    b, eax

const char sbox[] = {
  '\xe0','\x4f','\xd7','\x14','\x2e','\xf2','\xbd','\x81',
  '\x3a','\xa6','\x6c','\xcb','\x59','\x95','\x03','\x78',
  '\x4f','\x1c','\xe8','\x82','\xd4','\x69','\x21','\xb7',
  '\xf5','\xcb','\x93','\x7e','\x3a','\xa0','\x56','\x0d',

  '\xf3','\x1d','\x84','\xe7','\x6f','\xb2','\x38','\x4e',
  '\x9c','\x70','\x21','\xda','\xc6','\x09','\x5b','\xa5',
  '\x0d','\xe8','\x7a','\xb1','\xa3','\x4f','\xd4','\x12',
  '\x5b','\x86','\xc7','\x6c','\x90','\x35','\x2e','\xf9',

  '\xad','\x07','\x90','\xe9','\x63','\x34','\xf6','\x5a',
  '\x12','\xd8','\xc5','\x7e','\xbc','\x4b','\x2f','\x81',
  '\xd1','\x6a','\x4d','\x90','\x86','\xf9','\x38','\x07',
  '\xb4','\x1f','\x2e','\xc3','\x5b','\xa5','\xe2','\x7c',

  '\x7d','\xd8','\xeb','\x35','\x06','\x6f','\x90','\xa3',
  '\x14','\x27','\x82','\x5c','\xb1','\xca','\x4e','\xf9',
  '\xa3','\x6f','\x90','\x06','\xca','\xb1','\x7d','\xd8',
  '\xf9','\x14','\x35','\xeb','\x5c','\x27','\x82','\x4e',

  '\x2e','\xcb','\x42','\x1c','\x74','\xa7','\xbd','\x61',
  '\x85','\x50','\x3f','\xfa','\xd3','\x09','\xe8','\x96',
  '\x4b','\x28','\x1c','\xb7','\xa1','\xde','\x72','\x8d',
  '\xf6','\x9f','\xc0','\x59','\x6a','\x34','\x05','\xe3',

  '\xca','\x1f','\xa4','\xf2','\x97','\x2c','\x69','\x85',
  '\x06','\xd1','\x3d','\x4e','\xe0','\x7b','\x53','\xb8',
  '\x94','\xe3','\xf2','\x5c','\x29','\x85','\xcf','\x3a',
  '\x7b','\x0e','\x41','\xa7','\x16','\xd0','\xb8','\x6d',

  '\x4d','\xb0','\x2b','\xe7','\xf4','\x09','\x81','\xda',
  '\x3e','\xc3','\x95','\x7c','\x52','\xaf','\x68','\x16',
  '\x16','\x4b','\xbd','\xd8','\xc1','\x34','\x7a','\xe7',
  '\xa9','\xf5','\x60','\x8f','\x0e','\x52','\x93','\x2c',

  '\xd1','\x2f','\x8d','\x48','\x6a','\xf3','\xb7','\x14',
  '\xac','\x95','\x36','\xeb','\x50','\x0e','\xc9','\x72',
  '\x72','\xb1','\x4e','\x17','\x94','\xca','\xe8','\x2d',
  '\x0f','\x6c','\xa9','\xd0','\xf3','\x35','\x56','\x8b'
};



class des {
// DES machine

protected:
  typedef unsigned __int32 dword;
  struct qword {
    dword l;
    dword h;
  } iph, pc1h;

private:
  void keyshftl(); // pc1h
  void keyshftr(); // pc1h
  void swap_lr(); // iph
  void des_round(); // iph

public:
  void deskey(const char *); // pc1h
  void desxor(const char *); // iph
  void dessto(const char *m) // iph
    { iph.h = iph.l = 0, desxor(m); }
  void desrcl(char *) const;
  void desenc(); // iph
  void desdec(); // iph
};

__declspec(naked)
void des::keyshftl()
{
    __asm {				// ecx = this
	    bt	    [ecx].pc1h.h, 27
	    rcl	    [ecx].pc1h.h, 1
	    mov	    eax, [ecx].pc1h.l
	    shr	    eax, 4
	    bt	    eax, 27
	    rcl	    eax, 5
	    mov	    [ecx].pc1h.l, eax
	    ;mov    eax, ecx
	    ret
    }
}

__declspec(naked)
void des::keyshftr()
{
    __asm {				// ecx = this
	    mov	    eax, [ecx].pc1h.h
	    shl	    eax, 4
	    bt	    eax, 4
	    rcr	    eax, 5
	    mov	    [ecx].pc1h.h, eax
	    bt	    [ecx].pc1h.l, 4
	    rcr	    [ecx].pc1h.l, 1
	    ;mov    eax, ecx
	    ret
    }
}

__declspec(naked)
void des::swap_lr()
{
    __asm {				// ecx = this
	    mov	    eax, [ecx].iph.l
	    xchg    [ecx].iph.h, eax
	    mov	    [ecx].iph.l, eax
	    ;mov    eax, ecx
	    ret
    }
}

__declspec(naked)
void des::des_round()
{
    __asm {				// ecx = this
	    push    ebx
	    push    esi

keyred2:
	    mov	    eax, [ecx].pc1h.h

	    bt	    eax, 28-14
	    rcl	    esi, 1
	    bt	    eax, 28-17
	    rcl	    esi, 1
	    bt	    eax, 28-11
	    rcl	    esi, 1
	    bt	    eax, 28-24
	    rcl	    esi, 1
	    bt	    eax, 28-1
	    rcl	    esi, 1
	    bt	    eax, 28-5
	    rcl	    esi, 1
	    shl	    esi, 2

	    bt	    eax, 28-3
	    rcl	    esi, 1
	    bt	    eax, 28-28
	    rcl	    esi, 1
	    bt	    eax, 28-15
	    rcl	    esi, 1
	    bt	    eax, 28-6
	    rcl	    esi, 1
	    bt	    eax, 28-21
	    rcl	    esi, 1
	    bt	    eax, 28-10
	    rcl	    esi, 1
	    shl	    esi, 2

	    bt	    eax, 28-23
	    rcl	    esi, 1
	    bt	    eax, 28-19
	    rcl	    esi, 1
	    bt	    eax, 28-12
	    rcl	    esi, 1
	    bt	    eax, 28-4
	    rcl	    esi, 1
	    bt	    eax, 28-26
	    rcl	    esi, 1
	    bt	    eax, 28-8
	    rcl	    esi, 1
	    shl	    esi, 2

	    bt	    eax, 28-16
	    rcl	    esi, 1
	    bt	    eax, 28-7
	    rcl	    esi, 1
	    bt	    eax, 28-27
	    rcl	    esi, 1
	    bt	    eax, 28-20
	    rcl	    esi, 1
	    bt	    eax, 28-13
	    rcl	    esi, 1
	    bt	    eax, 28-2
	    rcl	    esi, 1
	    shl	    esi, 2

	    mov	    eax, [ecx].pc1h.l

	    bt	    eax, 60-41
	    rcl	    edx, 1
	    bt	    eax, 60-52
	    rcl	    edx, 1
	    bt	    eax, 60-31
	    rcl	    edx, 1
	    bt	    eax, 60-37
	    rcl	    edx, 1
	    bt	    eax, 60-47
	    rcl	    edx, 1
	    bt	    eax, 60-55
	    rcl	    edx, 1
	    shl	    edx, 2

	    bt	    eax, 60-30
	    rcl	    edx, 1
	    bt	    eax, 60-40
	    rcl	    edx, 1
	    bt	    eax, 60-51
	    rcl	    edx, 1
	    bt	    eax, 60-45
	    rcl	    edx, 1
	    bt	    eax, 60-33
	    rcl	    edx, 1
	    bt	    eax, 60-48
	    rcl	    edx, 1
	    shl	    edx, 2

	    bt	    eax, 60-44
	    rcl	    edx, 1
	    bt	    eax, 60-49
	    rcl	    edx, 1
	    bt	    eax, 60-39
	    rcl	    edx, 1
	    bt	    eax, 60-56
	    rcl	    edx, 1
	    bt	    eax, 60-34
	    rcl	    edx, 1
	    bt	    eax, 60-53
	    rcl	    edx, 1
	    shl	    edx, 2

	    bt	    eax, 60-46
	    rcl	    edx, 1
	    bt	    eax, 60-42
	    rcl	    edx, 1
	    bt	    eax, 60-50
	    rcl	    edx, 1
	    bt	    eax, 60-36
	    rcl	    edx, 1
	    bt	    eax, 60-29
	    rcl	    edx, 1
	    bt	    eax, 60-32
	    rcl	    edx, 1
	    shl	    edx, 2

	    ;ret

dtenlag:
/* (Eric Young's idea)
  R contains 32 bits that are input into the E function. If you look at the
  E function,
  32  1  2  3  4  5
   4  5  6  7  8  9
   8  9 10 11 12 13
  12 13 14 15 16 17
  16 17 18 19 20 21
  20 21 22 23 24 25
  24 25 26 27 28 29
  28 29 30 31 32  1

  If everything is first rotated up (ROR'd) by one before we begin, the E
  translation becomes
   1  2  3  4  5  6
   5  6  7  8  9 10
   9 10 11 12 13 14
  13 14 15 16 17 18
  17 18 19 20 21 22
  21 22 23 24 25 26
  25 26 27 28 29 30
  29 30 31 32  1  2

  Which you will notice relates to
   1  2  3  4  5  6    7  8
   5  6  7  8  9 10   11 12 
   9 10 11 12 13 14   15 16
  13 14 15 16 17 18   19 20
  17 18 19 20 21 22   23 24
  21 22 23 24 25 26   27 28
  25 26 27 28 29 30   31 32
  29 30 31 32  1  2    3  4

  So if we organise the 48 bits in the K table to occupy 2 32-bit words with
  the 1st, 3rd, 5th and 7th 6-bit groups padded with 2 bits so they are on 8
  byte boundaries, and the second word containing the even 6-bit groups aligned
  in the same way, except that the K data for the second word is rotated up
  4 bits, so
  u=R^K[word0]; t=R^K[word1]; produces
   1  2  3  4  5  6  *  *
   9 10 11 12 13 14  *  *
  17 18 19 20 21 22  *  *
  25 26 27 28 29 30  *  *
  and
   1  2  *  *  5  6  7  8  
   9 10  *  * 13 14 15 16
  17 18  *  * 21 22 23 24
  25 26  *  * 29 30 31 32
  which is then rotated by 4 to produce the required result
   5  6  7  8  9 10  *  *
  13 14 15 16 17 18  *  *
  21 22 23 24 25 26  *  *
  29 30 31 32  1  2  *  *
  These 8 'chunks' are used for looking up SPtrans (the input to the S tables).
*/
	    mov	    ebx, [ecx].iph.l
	    ror	    ebx, 1

	    shld    eax, ebx, 6
	    shl	    eax, 2
	    rol	    ebx, 4
	    shld    eax, ebx, 6
	    shl	    eax, 2
	    rol	    ebx, 4
	    shld    eax, ebx, 6
	    shl	    eax, 2
	    rol	    ebx, 4
	    shld    eax, ebx, 6
	    shl	    eax, 2
	    xor	    esi, eax
	    rol	    ebx, 4

	    shld    eax, ebx, 6
	    shl	    eax, 2
	    rol	    ebx, 4
	    shld    eax, ebx, 6
	    shl	    eax, 2
	    rol	    ebx, 4
	    shld    eax, ebx, 6
	    shl	    eax, 2
	    rol	    ebx, 4
	    shld    eax, ebx, 6
	    shl	    eax, 2
	    xor	    edx, eax

	    ;ret

sboxtrns:
	    push    ecx			// push this
	    sub	    ebx, ebx
	    mov	    cl, 7

lbl1:	    mov	    bh, cl
	    mov	    bl, dl
	    shrd    edx, esi, 8
	    shr	    esi, 8
	    shr	    ebx, 3
	    mov	    bl, sbox[ebx]
	    jc	    short lbl6
	    shr	    ebx, 4
lbl6:	    shrd    eax, ebx, 4
	    dec	    cl
	    jns	    short lbl1

	    ;ret

keytrse:
	    bt	    eax, 32-16
	    rcl	    edx, 1
	    bt	    eax, 32-7
	    rcl	    edx, 1
	    bt	    eax, 32-20
	    rcl	    edx, 1
	    bt	    eax, 32-21
	    rcl	    edx, 1
	    bt	    eax, 32-29
	    rcl	    edx, 1
	    bt	    eax, 32-12
	    rcl	    edx, 1
	    bt	    eax, 32-28
	    rcl	    edx, 1
	    bt	    eax, 32-17
	    rcl	    edx, 1

	    bt	    eax, 32-1
	    rcl	    edx, 1
	    bt	    eax, 32-15
	    rcl	    edx, 1
	    bt	    eax, 32-23
	    rcl	    edx, 1
	    bt	    eax, 32-26
	    rcl	    edx, 1
	    bt	    eax, 32-5
	    rcl	    edx, 1
	    bt	    eax, 32-18
	    rcl	    edx, 1
	    bt	    eax, 32-31
	    rcl	    edx, 1
	    bt	    eax, 32-10
	    rcl	    edx, 1

	    bt	    eax, 32-2
	    rcl	    edx, 1
	    bt	    eax, 32-8
	    rcl	    edx, 1
	    bt	    eax, 32-24
	    rcl	    edx, 1
	    bt	    eax, 32-14
	    rcl	    edx, 1
	    bt	    eax, 32-32
	    rcl	    edx, 1
	    bt	    eax, 32-27
	    rcl	    edx, 1
	    bt	    eax, 32-3
	    rcl	    edx, 1
	    bt	    eax, 32-9
	    rcl	    edx, 1

	    bt	    eax, 32-19
	    rcl	    edx, 1
	    bt	    eax, 32-13
	    rcl	    edx, 1
	    bt	    eax, 32-30
	    rcl	    edx, 1
	    bt	    eax, 32-6
	    rcl	    edx, 1
	    bt	    eax, 32-22
	    rcl	    edx, 1
	    bt	    eax, 32-11
	    rcl	    edx, 1
	    bt	    eax, 32-4
	    rcl	    edx, 1
	    bt	    eax, 32-25
	    rcl	    edx, 1

	    pop	    eax			// pop this
	    xor	    [eax].iph.h, edx

	    pop	    esi
	    pop	    ebx
	    ret
    }
}

__declspec(naked)
void des::deskey(const char *k)
{
    __asm {
	    push    ebx
	    mov	    ebx, ARG(1+1)	// ebx = k
	    mov	    edx, ecx		// edx = this
	    sub	    ecx, ecx
	    push    esi

	    mov	    esi, 7
	    call    xbu7
	    call    xbu7
	    call    xbu7
	    call    xbu7
	    mov	    [edx].pc1h.h, eax

	    mov	    cl, 4
	    sub	    esi, esi
	    call    xtdc
	    mov	    cl, 3
	    sub	    esi, esi
	    call    xtdc
	    call    xtd7
	    call    xtd7
	    call    xtd7
	    mov	    [edx].pc1h.l, eax

	    mov	    cl, 8
	    call    xtdc		// recover k
	    pop	    esi
	    pop	    ebx
	    ;mov    eax, edx
	    ret	    4

xbu7:
	    mov	    cl, 7
xbuc:	    rol	    byte ptr [ebx+esi], 1
	    rcl	    eax, 1
	    dec	    esi
	    and	    esi, 7
	    loop    short xbuc
	    ret

xtd7:
	    mov	    cl, 7
xtdc:	    rol	    byte ptr [ebx+esi], 1
	    rcr	    eax, 1
	    inc	    esi
	    and	    esi, 7
	    loop    short xtdc
	    ret
    }
}

__declspec(naked)
void des::desxor(const char *m)
// also converts little endian to big endian
{
    __asm   push    ebx
    __asm   mov     ebx, ARG(1+1)
    __asm   mov     edx, [ebx]
    __asm   mov     ebx, [ebx+4]

    PERM_OP(edx, ebx,  4, 0xf0f0f0f0 /* rol(0x0f0f0f0f,  4) */)
    PERM_OP(edx, ebx, 12, 0xffff0000 /* rol(0x0000ffff, 16) */)
    PERM_OP(edx, ebx, 18, 0xcccccccc /* rol(0x33333333,  2) */)
    PERM_OP(edx, ebx,  6, 0xff00ff00 /* rol(0x00ff00ff,  8) */)
    PERM_OP(edx, ebx, 25, 0xaaaaaaaa /* rol(0x55555555,  1) */)
    __asm   ror	    ebx, 1

    __asm   xor	    [ecx].iph.h, edx
    __asm   xor	    [ecx].iph.l, ebx
    __asm   pop	    ebx
    __asm   ret	    4
}
/*
{
    __asm {				// ecx = this
	    push    ebx
	    mov	    ebx, ARG(1+1)	// ebx = m
	    push    esi

	    call    xcol
	    call    xcol
	    call    xcol
	    call    xcol
	    xor	    [ecx].iph.h, edx
	    xor	    [ecx].iph.l, eax

	    pop	    esi
	    pop	    ebx
	    ;mov    eax, ecx
	    ret	    4

xcol:
	    mov	    esi, 7
lbl1:	    rol	    byte ptr [ebx+esi], 1
	    rcl	    eax, 1
	    dec	    esi
	    jns	    short lbl1
	    and	    esi, 7		// mov esi, 7
lbl6:	    rol	    byte ptr [ebx+esi], 1
	    rcl	    edx, 1
	    dec	    esi
	    jns	    short lbl6
	    ret
    }
}
*/

__declspec(naked)
void des::desrcl(char *c) const
{
    __asm {				// ecx = this
	    push    ebx
	    mov	    ebx, ARG(1+1)	// ebx = c
	    push    esi

	    mov	    edx, [ecx].iph.h
	    mov	    eax, [ecx].iph.l
	    call    icol
	    call    icol
	    call    icol
	    call    icol

	    pop	    esi
	    pop	    ebx
	    ;mov    eax, ecx
	    ret	    4

icol:
	    mov	    esi, 7
lbl1:	    shl	    eax, 1
	    rcl	    byte ptr [ebx+esi], 1
	    dec	    esi
	    jns	    short lbl1
	    and	    esi, 7		// mov esi, 7
lbl6:	    shl	    edx, 1
	    rcl	    byte ptr [ebx+esi], 1
	    dec	    esi
	    jns	    short lbl6
	    ret
    }
}

void des::desenc()
{
int i;

  keyshftl();
  des_round();
  for ( i = 0 ; i < 7 ; i++ ) {
    keyshftl();
    swap_lr();
    des_round();
    keyshftl();
  }
  swap_lr();
  des_round();
  keyshftl();
  for ( i = 0 ; i < 6 ; i++ ) {
    keyshftl();
    swap_lr();
    des_round();
    keyshftl();
  }
  swap_lr();
  des_round();
}

void des::desdec()
{
int i;

  des_round();
  for ( i = 0 ; i < 7 ; i++ ) {
    keyshftr();
    swap_lr();
    des_round();
    keyshftr();
  }
  swap_lr();
  des_round();
  keyshftr();
  for ( i = 0 ; i < 6 ; i++ ) {
    keyshftr();
    swap_lr();
    des_round();
    keyshftr();
  }
  swap_lr();
  des_round();
  keyshftr();
}



class des3 : public des {
// Triple-DES machine

protected:
  qword pc1l;

private:
  void keyxhg(); // pc1h, pc1l

public:
  void deskey(const char *, const char *); // pc1h, pc1l
  void desenc(); // iph
  void desdec(); // iph
};

__declspec(naked)
void des3::keyxhg()
{
    __asm {				// ecx = this
	    mov	    eax, [ecx].pc1h.l
	    xchg    [ecx].pc1l.l, eax
	    mov	    [ecx].pc1h.l, eax
	    mov	    eax, [ecx].pc1h.h
	    xchg    [ecx].pc1l.h, eax
	    mov	    [ecx].pc1h.h, eax
	    ;mov    eax, ecx
	    ret
    }
}

void des3::deskey(const char *ka, const char *kb)
{
  des::deskey(kb);
  pc1l = pc1h;
  des::deskey(ka);
  //return ( *this );
}

void des3::desenc()
{
  des::desenc();
  keyxhg();
  des::desdec();
  keyxhg();
  des::desenc();
  //return ( *this );
}

void des3::desdec()
{
  des::desdec();
  keyxhg();
  des::desenc();
  keyxhg();
  des::desdec();
  //return ( *this );
}



#define FIRST_PADDING_CHAR '\x80'

int unpadding(const char *buf)
/*
  parameters:
    buf = starting address to the buffer which contains 8 bytes of data with
	  padding (if any)
  remarks:
    does not change the contents of buf, but only calculates and returns the
    size of data with the padding excluded
  returns:
    (0 .. 8) size of data in bytes with the padding excluded
*/
{
int i;

  for ( i = 7 ; i >= 0 ; i-- )
    if ( buf[i] == FIRST_PADDING_CHAR )
      return ( i ); // (0 .. 7) padding found
    else if ( buf[i] )
      break;
  return ( 8 ); // padding not found
}

#include <assert.h> // assert()

char *padding(char *buf, int cnt)
/*
  parameters:
   - buf = starting address to the data buffer
   - cnt = (0 .. 7) number of bytes of data in buf
     if cnt == 0, buf contains 8 bytes of data which have been last processed,
     or encrypted
  remarks:
   - always appends padding to the end of data in buf if cnt > 0 && cnt < 8
   - if cnt == 0, reads in 8 bytes of data from buf, applies the padding rule,
     and replaces the data in buf with 0x80, 0x00, 0x00, ... if padding is
     determined to be needed
  returns:
   - 0 if no padding needed
   - buf if padded
  padding rule:
   - [XX XX XX XX XX] -> [XX XX XX XX XX 80 00 00]
   - [XX XX XX XX XX 80 00 00] + [80 00 00 00 00 00 00 00]
   - [XX XX XX XX XX 01 00 00] + no padding
   - [00 00 00 00 00 00 00 00] + no padding
*/
{
  assert(cnt >= 0 && cnt < 8);

  if ( cnt == 0 && unpadding(buf) == 8 )
    return ( 0 ); // no padding needed

  buf[cnt] = FIRST_PADDING_CHAR;
  while ( ++cnt < 8 )
    buf[cnt] = 0;
  return ( buf ); // padded
}



#include <fstream.h>
#include <iostream.h>
#include <time.h>

#define FIRST_KEY_CHAR '0'

void main(int argc, char *argv[])
{
#if 0
ifstream ifile;
ofstream ofile;
des cipher;
char key[8];
char buf1[8];
char buf2[8];
int i = 0;
char key0 = FIRST_KEY_CHAR;
bool encrypt = true;

  while ( *++argv && (*argv)[0] == '-' )
    switch ( (*argv)[1] ) {
      case 'D' :
      case 'd' :
	encrypt = false;
	break;

      case 'E' :
      case 'e' :
	encrypt = true;
	break;

      case 'K' :
      case 'k' :
	if ( argv[1] ) {
	  argv++;
	  for ( i = 0 ; i < 8 && (*argv)[i] ; i++ )
	    key[i] = (key0 = (*argv)[i]) << 1;
	}
	break;

      default :
	cerr << "Error: unknown option \"" << *argv << "\"\n";
	return;
    }

  if ( !argv[0] || !argv[1] || argv[2] ) {
    cerr <<
      "Usage:\tDES386 [-options] [-k keystring] inputfile outputfile\n"
      "\n"
      " -d\tdecryption\n"
      " -e\tencryption (default)\n";
    return;
  }

  for ( ; i < 8 ; i++ )
    key[i] = (++key0) << 1;
  cipher.deskey(key);

/* (does not seem to be faster)
  if ( !ifile.setbuf(cache1, sizeof(cache1))
    || !ofile.setbuf(cache2, sizeof(cache2)) ) {
    cerr << "Error: cannot allocate caches\n";
    return;
  }
*/
  ifile.open(argv[0], ios::in|ios::nocreate|ios::binary);
  if ( !ifile ) {
    cerr << "Error: cannot read \"" << argv[0] << "\"\n";
    return;
  }
  ofile.open(argv[1], ios::out|ios::binary);
  if ( !ofile ) {
    cerr << "Error: cannot write to \"" << argv[1] << "\"\n";
    return;
  }

  cerr << "Processing...";

  clock_t start = clock();
  if ( encrypt ) {
    /* encryption using single-DES ECB mode */
    while ( (i = ifile.read(buf1, 8).gcount()) == 8 ) {
      cipher.dessto(buf1);
      cipher.desenc();
      cipher.desrcl(buf2);
      ofile.write(buf2, 8);
    }
    if ( padding(buf1, i) ) {
      cipher.dessto(buf1);
      cipher.desenc();
      cipher.desrcl(buf2);
      ofile.write(buf2, 8);
    }
  } else {
    /* decryption using single-DES ECB mode */
    while ( (i = ifile.read(buf1, 8).gcount()) == 8 && ifile.peek() != EOF ) {
      cipher.dessto(buf1);
      cipher.desdec();
      cipher.desrcl(buf1);
      ofile.write(buf1, 8);
    }
    if ( i != 8 ) {
      cerr << "\nError:\tmay not be des-encrypted\n";
      return;
    }
    cipher.dessto(buf1);
    cipher.desdec();
    cipher.desrcl(buf1);
    ofile.write(buf1, unpadding(buf1));
  }
  clock_t finish = clock();

  cerr << "\rDone.        \n";

  cerr << "(TIME = " << (double)(finish-start)/CLOCKS_PER_SEC << ")\n";

  if ( ifile.get() != EOF || !ifile.eof() || ifile.bad() )
    cerr << "Error:\tbut something strange happened\n";

  ifile.close();
  ofile.close();
#endif
char k[8] =
{ '\x13','\x34','\x57','\x79','\x9b','\xbc','\xdf','\xf1' };
char l[8] =
{ '\x14','\x35','\x58','\x7a','\x9c','\xbd','\xe0','\xf2' };
char m[8] =
{ '\x01','\x23','\x45','\x67','\x89','\xab','\xcd','\xef' };
des3 A;

  A.deskey(k,l);
  A.dessto(m);
  A.desenc();
  A.desdec();
  A.desrcl(m);
}



/*
Argument Passing and Naming Conventions
Home |  Overview |  How Do I

All arguments are widened to 32 bits when they are passed. Return values are
also widened to 32 bits and returned in the EAX register, except for 8-byte
structures, which are returned in the EDX:EAX register pair. Larger structures
are returned in the EAX register as pointers to hidden return structures.
Parameters are pushed onto the stack from right to left.

The compiler generates prolog and epilog code to save and restore the ESI, EDI,
EBX, and EBP registers, if they are used in the function.

Note   For information on how to define your own function prolog and epilog
code, see Naked Function Calls.

The following calling conventions are supported by the Visual C/C++ compiler.

Keyword	    Stack cleanup   Parameter passing
__cdecl	    Caller	    Pushes parameters on the stack, in reverse order
			    (right to left)
__stdcall   Callee	    Pushes parameters on the stack, in reverse order
			    (right to left)
__fastcall  Callee	    Stored in registers, then pushed on stack
thiscall    Callee	    Pushed on stack; this pointer stored in ECX
			    (not a keyword)

For related information, see Obsolete Calling Conventions.

Send feedback to MSDN. Look here for MSDN Online Resources.

¨Ï 1999 Microsoft Corporation. All rights reserved. Terms of use.
*/

/*
thiscall
Home |  Overview |  How Do I

This is the default calling convention used by C++ member functions that do not
use variable arguments. The callee cleans the stack, so the compiler makes
vararg functions __cdecl, and pushes the this pointer on the stack last.
The thiscall calling convention cannot be explicitly specified in a program,
because thiscall is not a keyword.

All function arguments are pushed on the stack. Because this calling convention
applies only to C++, there is no C name decoration scheme.

Send feedback to MSDN. Look here for MSDN Online Resources.

¨Ï 1999 Microsoft Corporation. All rights reserved. Terms of use.
*/
