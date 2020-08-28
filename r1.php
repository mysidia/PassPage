<?php
exit(0);

header('Content-type: text/html; charset=utf-8');
header('Surrogate-Control: BigPipe/1.0');
header("Cache-Control: no-cache, must-revalidate");
header('X-Accel-Buffering: no');
flush();
ini_set('output_buffering', 'Off');
ini_set('zlib.output_compression', 'Off');

$f = crack_opendict("/usr/share/dict/crack1");
echo "crack_check = " . crack_check("test12", "user", "user gecos", $f);
#bool crack_check ( string $password , string $username = "" , string $gecos = "" , resource $dictionary = NULL )

echo "\n";

?>
