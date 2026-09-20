;*****************************************************************
;
; Формат режима знакоместа
; Адрес тот же
;
;       Байт 0
;               bit 7..6 - номер палитры
;               bit 5 - графика/текст, должно быть 1 (текста нет)
;               bit 4 - режим 640/320 точек в линии
;               bit 3 - резерв - должны быть 0
;               bit 2 - разрешение смещения сетки
;               bit 1..0 - 2 старших бита координаты X
;
;       Байт 1  8 младших бит координаты X
;
;       Байт 2  координата Y
;
;       Байт 3  смещение сетки координат 
;               bit 3..0 - смещение по X
;               bit 7..4 - смещение по Y
;
;       Квадратик графики 8x8 выводится из виртуального экрана 1024x256
;               в соответствии с координатами верхнего левого
;               угла знакоместа, заданного в байтах режима
;
;       Смещение сетки задается третьим байтом режима экрана
;       Действует только, сопровождаемый единицей 
;       в бите 2 нулевого байта режима
;       Если бит 2 не был установлен, то смещение 
;       ОСТАЕТСЯ ТЕМ, ЧТО БЫЛО УСТАНОВЛЕНО РАНЕЕ
;       Действие байта заданного в знакоместе включается на следующем 
;       знакоместе
;       
;                                                       Ivan Makarchenko
;*****************************************************************



; Опыт 640x256 / 16 цветов, 21.09.2026.
; Описание битов 5/4 выше - исходное описание автора конфигурации.
; SCROLL_MODE_BITS=#30: bit5=1, bit4=1, проба 640 по этому описанию.
; SCROLL_MODE_BITS=0:   bit5=0, bit4=0, контроль по базовому VIDEO2.
; Для скролл-конфигурации выбор 640 еще должен быть проверен на плате.
; В обоих вариантах байт пикселей содержит два индекса цвета по 4 бита.
; X задается в байтах: квадрат 8x8 занимает 4 байта на 8 строк.
; Заполняются все 80 позиций описателей, без пропущенных четных колонок.
; Менять вариант: sjasmplus -DSCROLL_MODE_BITS=0 ... Scroll.asm

; Подгрузка файла с константами BIOS и DSS:
 INCLUDE 'shared_includes/constants/SP2000.inc'
 INCLUDE 'shared_includes/macroses/accelerator.z80'
 INCLUDE 'shared_includes/constants/dss_equ.inc'
 INCLUDE 'shared_includes/constants/bios_equ.inc'

 define KEYBOARD_IS 0
 IFNDEF SCROLL_MODE_BITS
SCROLL_MODE_BITS EQU #30
 ENDIF
SCROLL_START EQU #4180 | (SCROLL_MODE_BITS << 8)
DISPLAY_COLS EQU 80
Loader_length	EQU 0
code_addr	EQU START
program_start	EQU START
stack_point	EQU #C000
stack_size	EQU #100                              
org_addr	EQU #8000 + CLP_Buffer                                             

;   _______  _______   ____            __ _      
;  | ____\ \/ / ____| |  _ \ _ __ ___ / _(_)_  __
;  |  _|  \  /|  _|   | |_) | '__/ _ \ |_| \ \/ /
;  | |___ /  \| |___  |  __/| | |  __/  _| |>  < 
;  |_____/_/\_\_____| |_|   |_|  \___|_| |_/_/\_\

;*******************************************************
	INCLUDE	'Shared_Includes/constants/EXE_Header.z80'
        ORG	org_addr
;   __  __       _       
;  |  \/  | __ _(_)_ __  
;  | |\/| |/ _` | | '_ \ 
;  | |  | | (_| | | | | |
;  |_|  |_|\__,_|_|_| |_|

START:	; LD A,CNF_0
        ; OUT (SYS_PORT.OFF),A
	IN	A,(SCREEN_SWITCH)
	LD	(EXIT_DSS.switch_scr),A
	XOR	A
	OUT	(SCREEN_SWITCH),A

        LD      C,BIOS.SET_PAL_INIT ; установка палитры
        LD      A,1
        LD      B,1
        RST     ToBIOS

        LD      C,BIOS.SET_PAL_INIT
        LD      A,0
        LD      B,1
        RST     ToBIOS

        LD      C,BIOS.SET_PAL_INIT
        LD      A,2
        LD      B,1
        RST     ToBIOS

        LD      C,BIOS.SET_PAL_INIT
        LD      A,3
        LD      B,1
        RST     ToBIOS
                                        

        ; Первые 16 цветов графической палитры 1: B,G,R,0.
        LD HL,PAL640
        LD DE,#1000             ; D=16 цветов, E=первый цвет 0
        LD B,#FF                ; маска записи
        LD A,1                  ; графическая палитра 1
        LD C,BIOS.PIC_SET_PAL
        RST ToBIOS

        IN A,(SLOT3)            ; сохранить порты
        PUSH AF
        IN A,(PORT_Y)
        PUSH AF

        LD A,#50
        OUT (SLOT3),A           ; экран в SLOT3

        CALL CLEAR_SH           ; очистка 4-го байта режима экрана

        LD A,0                  ; координата Y
        LD DE,SCROLL_START      ; X=#180, палитра 1, проба режима 640

        CALL MAIN_SCROLL        ; задание нового граф.режима

        CALL PIC_SET            ; прорисовка картинки (сетка)

        LD A,0                  ; координата Y
        LD DE,SCROLL_START      ; X=#180, палитра 1, проба режима 640
        LD BC,100               ; число фреймов до выхода C*256
LOOP_SCR:
        PUSH AF
        PUSH DE
        PUSH BC

        CALL MAIN_SCROLL2       ; новый скроллинг

        POP BC
        POP DE

        LD A,1                  ; меняем координату X
ADD_PAR2 EQU $-1

        ADD A,E
        LD E,A
        CP #FF
        JR NZ,NO_X1
        LD A,-1
        LD (ADD_PAR2),A
NO_X1:
        CP 0
        JR NZ,NO_X2
        LD A,1
        LD (ADD_PAR2),A
NO_X2:
        POP AF
        ADD A,1                 ; меняем координату Y
ADD_PAR1 EQU $-1

        PUSH AF

        CP #F0
        JR NZ,NO_X3
        LD A,-1
        LD (ADD_PAR1),A
NO_X3:
        CP 0
        JR NZ,NO_X4
        LD A,1
        LD (ADD_PAR1),A
NO_X4:

        LD A,7
        OUT (BorderColor),A     ; бордерная указка

        EI
        HALT

        LD A,0
        OUT (BorderColor),A

;-----------------; опрос клавиатуры
 IF KEYBOARD_IS
;-PC Keyboard-;
;
        di

        push bc
        push de
        push hl
        ld c,Dss.ScanKey
        rst ToDSS
        pop hl
        pop de
        pop bc

        ei

        jr z,1F
        pop af
        jp 2F   
;       
;-------------;                 ; выход, если нажата любая клавиша
 ELSE
;-ZX Keyboard-;
;
	push bc
	ld bc,Port_All_Mode
	in a,(c)
	and #FE
	out (c),a

        ld a,#7f
        in a,(#FE)
        rrca

	in a,(c)
	set 0,a
	out (c),a
	pop bc
	
        jp c,1F
        pop af
        jp 2F
;
;-------------;
 ENDIF
;-----------------;

1:
        POP AF

        DJNZ LOOP_SCR
        DEC C
        JR NZ,LOOP_SCR

2:
;-----------------; Выход
        POP AF                  ; восстановить порты
        OUT (PORT_Y),A
        POP AF
        OUT (SLOT3),A

EXIT_DSS:
.switch_scr+1:
	LD	A,0
	OUT	(SCREEN_SWITCH),A
        ld bc,Dss.Exit
        rst ToDSS

        RET

;******************************************

MAIN_SCROLL2:
        DI

        IN A,(PORT_Y)
        PUSH AF

        LD HL,#C310     ; начиная с 4-й строки сверху
LOOP_SC1:
        LD A,5          ; позиция 5 из 80; команда действует со следующей
                        ; Границы окна и значения D3 сохранены от теста 320.

        OUT (PORT_Y),A

        LD A,(HL)
        OR %00000100
        LD (HL),A       ; установка бита 2 для включения смещения

        INC L
        INC L
        INC L
        LD A,(COUNT1)                       
        LD (HL),A       ; установка смещения

        INC L

        LD A,L
        CP #70          ; заканчиваем на 28-й строке
        JR NZ,LOOP_SC1


        LD HL,#C310     ; начиная с 4-й строки
LOOP_SC2:

        LD A,75         ; правая граница: позиция 75 из 80
        OUT (PORT_Y),A

        LD A,(HL)
        OR %00000100
        LD (HL),A       ; устанавливаем новое смещение

        INC L
        INC L
        INC L
        LD (HL),#88     ; оба поля смещения = 8, как в исходном тесте
                        ; Единицу смещения X в 640 проверяем на плате.
        INC L

        LD A,L
        CP #78          ; заканчиваем на 30-й строке
                        ; (две лишних строки, что бы 
                        ; сработали байты в смещенном по 
                        ; вертикали знакоместе)
        JR NZ,LOOP_SC2

        POP AF
        OUT (PORT_Y),A


        LD A,(COUNT2)   ; "плавное" изменение счетчика для демонстрации
        ADD A,#40       ; смещения
        LD (COUNT2),A
        JR NC,no_add1
        LD A,(COUNT1)
        ADD A,#11
        AND #77
        LD (COUNT1),A
no_add1:
        RET

COUNT1: db 0
COUNT2: db 0

;******************************************************

CLEAR_SH:               ; забиваются нулями все 3-и байты режима
        IN A,(PORT_Y)   ; на всем экране (в том числе бордере и бланке!)
        PUSH AF         ; акселератором

        XOR A
        OUT (PORT_Y),A
        LD HL,#C303


CLEAR_LOOP:
        DI
        ACC_SetBlockSize
                LD A,0
        ACC_FillScreenOneByte
                LD (HL),A
        ACC_Off
        EI

        INC L
        INC L
        INC L
        INC L

        LD A,L
        CP #B3
        JR NZ,CLEAR_LOOP

        POP AF
        OUT (PORT_Y),A

        RET

;*********************************************

; Сетка квадратов 8x8 в упакованной графике 640x256 (4 bpp).
; Внутренние пиксели - цвета 1..14, рамка - цвет 15 (белый).
; Рисуем только X=0..#2FF: служебная область #C300 не затрагивается.
PIC_SET:
        IN A,(PORT_Y)
        PUSH AF
        DI

        LD HL,#C000             ; 4 байта = 8 пикселей по горизонтали
        LD C,#11                ; два пикселя одного цвета
PIC_COLUMN:
        XOR A                   ; Y=0
PIC_SQUARE:
        LD B,8                  ; восемь строк одного квадрата
PIC_ROW:
        OUT (PORT_Y),A
        PUSH AF
        AND 7
        JR Z,PIC_BORDER         ; верхняя горизонтальная рамка
        CP 7
        JR Z,PIC_BORDER         ; нижняя горизонтальная рамка

        PUSH HL
        LD A,C
        OR #F0                  ; левый край: белый + цвет
        LD (HL),A
        INC HL
        LD (HL),C
        INC HL
        LD (HL),C
        INC HL
        LD A,C
        OR #0F                  ; правый край: цвет + белый
        LD (HL),A
        POP HL
        JR PIC_NEXT_ROW
PIC_BORDER:
        ACC_SetBlockSize
                LD A,4
        ACC_Off
        LD A,#FF                ; восемь белых пикселей
        ACC_FillOneByte
                LD (HL),A
        ACC_Off
PIC_NEXT_ROW:
        POP AF
        INC A
        DJNZ PIC_ROW

        PUSH AF                 ; следующий цвет, от 1 до 14
        LD A,C
        AND #0F
        INC A
        CP 15
        JR C,PIC_COLOR
        LD A,1
PIC_COLOR:
        LD C,A
        RLCA
        RLCA
        RLCA
        RLCA
        OR C
        LD C,A                  ; одинаковый индекс в обоих полубайтах
        POP AF
        AND A
        JR NZ,PIC_SQUARE         ; до Y=255 включительно

        LD DE,4
        ADD HL,DE
        LD A,H
        CP #C3
        JR NZ,PIC_COLUMN

        POP AF
        OUT (PORT_Y),A
        RET

;*********************************************
; установка режима экрана
MAIN_SCROLL:                    ; A=Y, DE=X в байтах + режим
        CALL Y_SET
        CALL X_SET

        LD HL,#C302             ; D2 первой строки описателей
        LD BC,Y_DATA
M_LOOP:
        PUSH HL
        XOR A                   ; все позиции PORT_Y=0..79
        OUT (PORT_Y),A

        DI
        ACC_SetBlockSize
                LD A,DISPLAY_COLS
        ACC_Off
        LD A,(BC)
        ACC_FillScreenOneByte
                LD (HL),A       ; D2: одинаковый Y во всей строке
        ACC_Off
        IN A,(PORT_Y)
        OUT (PORT_Y),A

        DEC L
        LD DE,X_DATA
        ACC_CopyBlock
                LD A,(DE)
        ACC_CopyScreenBlock
                LD (HL),A       ; D1: младший байт X
        ACC_Off
        IN A,(PORT_Y)
        OUT (PORT_Y),A

        DEC L
        LD DE,MODE_DATA
        ACC_CopyBlock
                LD A,(DE)
        ACC_CopyScreenBlock
                LD (HL),A       ; D0: режим + старшие биты X
        ACC_Off
        IN A,(PORT_Y)
        OUT (PORT_Y),A

        POP HL
        INC L
        INC L
        INC L
        INC L
        INC BC
        LD A,L
        CP #82
        JR NZ,M_LOOP
        EI
        RET

;******************************************
Y_SET:                          ; A - Y_coord
        LD HL,Y_DATA            ; адрес данных
        LD B,32
M_LP1:
        LD (HL),A               ; Y координаты для всех квадратиков одной строки
        INC HL
        ADD A,8                 ; увеличить на 8 для следующей строки
        DJNZ M_LP1
        RET

;******************************************

X_SET:                          ; DE - X в байтах + MODE
        PUSH IX
        LD HL,X_DATA
        LD IX,MODE_DATA
        LD B,DISPLAY_COLS
M_LPX1:
        LD (HL),E
        LD (IX+0),D
        INC HL
        INC IX
        LD A,E
        ADD A,4                 ; 4 байта = 8 пикселей в режиме 640
        LD E,A
        LD A,D
        ADC A,0
        LD D,A
        DJNZ M_LPX1
        POP IX
        RET

; 16 цветов. Запись для BIOS.PIC_SET_PAL: B,G,R,0.
PAL640:
        DB #00,#00,#00,0,  #AA,#00,#00,0
        DB #00,#AA,#00,0,  #AA,#AA,#00,0
        DB #00,#00,#AA,0,  #AA,#00,#AA,0
        DB #00,#55,#AA,0,  #AA,#AA,#AA,0
        DB #55,#55,#55,0,  #FF,#55,#55,0
        DB #55,#FF,#55,0,  #FF,#FF,#55,0
        DB #55,#55,#FF,0,  #FF,#55,#FF,0
        DB #55,#FF,#FF,0,  #FF,#FF,#FF,0

X_DATA:         DS DISPLAY_COLS ; D1, младшие байты X
MODE_DATA:      DS DISPLAY_COLS ; D0, режим и старшие биты X
Y_DATA:         DS 32           ; D2, Y для 32 строк
;