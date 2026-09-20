program transttf;

{$APPTYPE CONSOLE}

uses
  Convert,
  CLasses;

var
  fb: file;
  f: textfile;
  s: string;
  tsl: TStringList;
  i, k: longint;
  b: byte;
  buf: array[0..1000] of byte;
begin
  writeln('transform ttf-file to binary');
  writeln('Copyright (c) 2021 Sprinter Team');

  if ParamCount < 1 then
  begin
    writeln('usage:');
    writeln('  transttf.exe <in_file> <out_file>');
    exit;
  end;

{$I-}
  if ParamStr(2) <> '' then
    AssignFile(fb, ParamStr(2))
  else
    AssignFile(fb, ParamStr(1)+'.bin');
  rewrite(fb, 1);

  AssignFile(f, ParamStr(1));
  reset(f);

  i:= 1;
  while not EOF(f) do
  begin
    readln(f, s);

    if s[length(s)] <> ',' then
      s:= s + ',';

    tsl:= TStringList.Create;
    tsl.Delimiter:= ','; //comma delimiter
    tsl.QuoteChar:= #0;
    tsl.StrictDelimiter := True;
    tsl.DelimitedText:= s;

//    writeln('count: '+strr(tsl.Count)+', s=['+s+']');

    for k:= 0 to sizeof(buf) do
      buf[k]:= 0;

    for k:= 0 to tsl.Count-1 do
    begin
      b:= vall(tsl.Strings[k]);
      buf[k]:= b;
    end;

    BlockWrite(fb, buf, tsl.Count-1);

    inc(i);
  end;


  CloseFile(f);

  CloseFile(fb);

  IOResult;
{$I+}

  writeln('transform done.');
end.