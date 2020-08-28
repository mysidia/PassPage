<?php
/*
 * Copyright (C) Mysidia, 2015, All Rights Reserved
 *
 * Create Hashes.
 * Requires xzcvbn-c
 * 
 */
require 'pbkdf2.php';
require 'config.php';
$textvalSec = '';
$requestfile = '';

date_default_timezone_set('US/Central');

if (empty($_POST['kc']) ||  empty( $HASHMAKER_kc[$_POST['kc']] )) {
       echo '<PRE>A valid kc code or  API key is required to invoke this page.</PRE>' . "\n";
       exit(1);
}


header('Content-type: text/html; charset=utf-8');
header('Surrogate-Control: BigPipe/1.0');
header("Cache-Control: no-cache, must-revalidate");
header('X-Accel-Buffering: no');
flush();
ini_set('output_buffering', 'Off');
ini_set('zlib.output_compression', 'Off');
$textval = '';
$textval0 = '';

function score_desc($score)
{
     $desc = '';
         if ($score == 0) {
             $desc .= 'Did you type anything in the box?';
         } else if ($score == 1) {
             $desc .= 'Very guessable -- password is terribly weak';
         } else if ($score == 2) {
             $desc .= 'Somewhat guessable -- password is below minimum strength';
         } else if ($score == 3) {
             $desc .= 'Questionably unguessable -- password is below minimum strength';
         } else if ($score == 4) {
             $desc .= 'Apparently strong (as far as we can tell)....';
         }

     return $desc;
}

function zeroFill($a,$b) {
    if ($a >= 0) { 
        return bindec(decbin($a>>$b)); //simply right shift for positive number
    }

    $bin = decbin($a>>$b);

    $bin = substr($bin, $b); // zero fill on the left side

    $o = bindec($bin);
    return $o;
}

function asa_b64($Input) {
   $tab = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
   $output1 = "";
   $len = strlen($Input);
   $i = 0;
   $j = 0;
   $chunk32 = 0; 

#        $i, $j, $chunk32;

    for ($i = 0; $i < $len; $i = $i + 4) {
        $chunk32 = ( ord($Input[$i + 3]) << 24)
                    | (ord($Input[$i + 2]) << 16)
                    | (ord($Input[$i + 1]) << 8)
                    | (ord($Input[$i]));
        for ($j = 0; $j < 4; $j = $j + 1) {
            $output1 .=  $tab[ zeroFill($chunk32, (6 * $j)) & 0x3F ];
        }
    }
    return $output1;
}


function PixHash($Input, $Uname) {
      $p = $Input . substr($Uname,0,4);
      $pl = 16;

      if ( strlen($Input) > 12) { $pl = 32; }

      if (strlen($p) > $pl) {
          $p = substr($Input, 0, $pl);
      }

      if ( strlen($Input) < 28 ) {
          $hash = md5( str_pad($p, $pl, "\0"), true );
      } else { 
          $hash = md5( str_pad(substr($Input,0,$pl), $pl, "\0"), true );
      }

      if ( strlen($Input) > 32 )  {
          return 'ERROR{TOO_LONG} ' . asa_b64($hash);
      }
      return asa_b64($hash);
}

function NTLMHash($Input) {
  // Convert the password from UTF8 to UTF16 (little endian)
  $Input=iconv('UTF-8','UTF-16LE',$Input);

  // Encrypt it with the MD4 hash
  $MD4Hash=bin2hex(mhash(MHASH_MD4,$Input));

  // You could use this instead, but mhash works on PHP 4 and 5 or above
  // The hash function only works on 5 or above
  //$MD4Hash=hash('md4',$Input);

  // Make it uppercase, not necessary, but it's common to do so with NTLM hashes
  $NTLMHash=strtoupper($MD4Hash);

  // Return the result
  return($NTLMHash);
}

function LMhash($string)
{
    $string = strtoupper(substr($string,0,14));

    $p1 = LMhash_DESencrypt(substr($string, 0, 7));
    $p2 = LMhash_DESencrypt(substr($string, 7, 7));

    return strtoupper($p1.$p2);
}

function LMhash_DESencrypt($string)
{
    $key = array();
    $tmp = array();
    $len = strlen($string);

    for ($i=0; $i<7; ++$i)
        $tmp[] = $i < $len ? ord($string[$i]) : 0;

    $key[] = $tmp[0] & 254;
    $key[] = ($tmp[0] << 7) | ($tmp[1] >> 1);
    $key[] = ($tmp[1] << 6) | ($tmp[2] >> 2);
    $key[] = ($tmp[2] << 5) | ($tmp[3] >> 3);
    $key[] = ($tmp[3] << 4) | ($tmp[4] >> 4);
    $key[] = ($tmp[4] << 3) | ($tmp[5] >> 5);
    $key[] = ($tmp[5] << 2) | ($tmp[6] >> 6);
    $key[] = $tmp[6] << 1;
   
    $is = mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_ECB);
    $iv = mcrypt_create_iv($is, MCRYPT_RAND);
    $key0 = "";
   
    foreach ($key as $k)
        $key0 .= chr($k);
    $crypt = mcrypt_encrypt(MCRYPT_DES, $key0, "KGS!@#$%", MCRYPT_MODE_ECB, $iv);

    return bin2hex($crypt);
}

function entropy_to_score($entropy, $len){
   if ($len < 6 )
              return 0;

   if ( $entropy <= 9.96578428466209 || $entropy <= 10 )
        return 0;

   if ( $len < 8 )
              return 1;
   if ( $entropy <= 19.93156856932417  || $entropy <= 20 )
        return 1;
   if ( $entropy <= 26.5754247590989 || $entropy <= 27 )
         return 2;
   if ( $entropy <= 33.21928094887362 || $entropy <= 38 )
         return 3;
   return 4;
}

$secval = $_POST['pw2hash'];

$fdd = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w")
);
$proc = proc_open("/usr/local/bin/zxcvbn-checkpass", $fdd, $pipes, '/tmp', array());

if (strlen($secval) <= 32) {
fwrite($pipes[0], $secval . "\n");
} else {
fwrite($pipes[0], substr($secval,0,32) . "\n");
}
fclose($pipes[0]);
$pwlen = -1;
$pwentropy = -1.0;
$n=1;

$textval0 = <<< 'EOT'

<script type="text/javascript">
function expandRawDetails()
{
   if ( $("#strengthdata").css("display") == "none"   )   {
      $("#showdetails").text("Hide raw Details");
       $("#strengthdata").show(true);
  } else {
      $("#showdetails").text("Show raw Details");
      $("#strengthdata").hide(true);
  }
}
</script>
EOT;


while(!feof($pipes[1])) {
   $line = fgets($pipes[1], 1024);

   if ( preg_match('/^LENGTH=(\d+)/', $line, $matches) ) {
         $pwlen = $matches[1];
   } else if ( preg_match('/^ENTROPY_BITS=(\S+)/', $line, $matches) ) {
         $pwentropy = $matches[1];
   } else if ( preg_match('/^\s*Type:\s+(.*) (.*)/', $line, $matches) ) {
         $textval0 .= "&nbsp;&nbsp*&nbsp;&nbsp; PathDepth=" . $n++ . " Attack - N-gram using  "  . $matches[1] . '<BR />';
   } else if ( preg_match('/^Pass (.*)\s+Length\s+(.*)/', $line, $matches) ) {
 $textval0 .= '<div style="background:lightgray; margin: 10px; width: 100%;"><span style="background:yellow; color:black;">SS2 Password Strength Score:<BR /> (' . entropy_to_score($pwentropy,$pwlen) . '/' . score_desc( entropy_to_score($pwentropy,$pwlen)) . ') [<a href="#" id="showdetails" onclick="expandRawDetails();">Show raw details</a>]</span><div style="display:none; width: 100%; margin 10px;" id="strengthdata"><br />';
         $myscore = entropy_to_score($pwentropy,$pwlen);

         $textval0 .= 'SCORE IS: ' . $myscore . ', Maximum entropy estimate for your password is: ' . $pwentropy . ' Bits of entropy (' . (int)($pwentropy*100/34) .  '% of the minimum for a strong password)<BR />';
         $textval0 .= 'Category: ';
         if ($myscore == 0) {
             $textval0 .= 'Did you type anything in the box?<br />';
         } else if ($myscore == 1) {
             $textval0 .= 'Very guessable -- password unacceptable<br /><br />';
         } else if ($myscore == 2) {
             $textval0 .= 'Somewhat guessable -- password unacceptable<br /><br />';
         } else if ($myscore == 3) {
             $textval0 .= 'Questionably unguessable<br />';
         } else if ($myscore == 4) {
             $textval0 .= 'Apparently strong (as far as we can tell)....  <br /><br />';
         }
         $textval0 .= 'Pass &lt;REDACTED&gt; Length ' . $matches[2]  . '<BR />';
         $textval0 .= 'Internal calculation of password cracking difficulty (zxcv-c__):<BR />';
   } else {
         $textval0 .= $line . '<BR />';
   }
}
fclose($pipes[1]);
proc_close($proc);
$textval0 .= '</div></div>';


$s0 = bin2hex(openssl_random_pseudo_bytes(4));
$s1 = bin2hex(openssl_random_pseudo_bytes(8));
$s2 = bin2hex(openssl_random_pseudo_bytes(8));
$s3 = bin2hex(openssl_random_pseudo_bytes(16));

$sshasalt = bin2hex(openssl_random_pseudo_bytes(2));



$bcrypt = new Bcrypt(15);
$bcrypth = $bcrypt->hash($secval);

$textval = '';

if (!empty($_POST['request'])) {
    $requestfile = 'REQUEST_'.md5($_POST['request']).'_'.time();
    $textval     = 'REQUEST ID ' . htmlspecialchars($_POST['request']) . '<br><br>';
}

$textval = $textval . '<div style="width: 100%;"><span class="sh1text">Computed Hash Values</span><br />';

$crypt1 = crypt($secval, '$1$' . $s1 . '$');
$ssha = '{ssha}' . base64_encode(pack('H*',sha1($secval . $sshasalt) ) . $sshasalt );

if ((empty($_POST['checkonly']) || $_POST['checkonly'] != 1) && $myscore >= 4)
{

  if ($_POST['hashtype']  == "SECURE")  {
       $ssha = '&lt;SSHA-REDACTED&gt;';
  }


$xnQQ = "HMAC." . sha1("OiVaPYLjqJxp" . $crypt1  . $_SERVER['REMOTE_ADDR'] . "1sVylnD1EDKW") . ":" . $_SERVER['REMOTE_ADDR'] . ":" . $ssha;

$textval .= "
A = [ " . $xnQQ .  " ]<BR />";
$textval .= "
B = [ " . $crypt1 .  " ]<BR />" .
"FP = [ " .  substr(hash_pbkdf2('sha1', $xnQQ, 'ayg0TA3', 4096, 256),0,6)  . " ]" .
 "<BR /><BR /><BR /> ";



if ($_POST['hashtype'] == "" || $_POST['hashtype'] == 'SECURE') {
$textval .= "
C = " . crypt($secval, '$6$' . $s2) . "<BR />
D = " . crypt($secval, '$6$rounds=10000$' . $s2) . "<BR />
";
}

} else if (!empty($_POST['checkonly'])) {
 $textval .= '<SPAN STYLE="color:red; font-weight: bold;">ERROR: Skipped hash calculation of A,B,C,D:  Sorry, Password too weak according to pre-evaluation.</SPAN><BR /><BR />';
} else if ($myscore < 4) {
 $textval .= '<SPAN STYLE="color:red; font-weight: bold;">ERROR: Skipped hash calculation of A,B,C,D:  Sorry, Password too weak.    Other hashes are shown only for reference.</SPAN><BR /><BR />';
}

if ($_POST['hashtype'] == "") {
$textval .= "
E = " . md5("KxZMcBYr2zPu" . $secval . "sR6ooEtSwYbX") . "<BR />";
} else {
$textvalSec .= "
E = " . md5("KxZMcBYr2zPu" . $secval . "sR6ooEtSwYbX") . "<BR />";
}

$textval .= "
<B>CISCO_PIX-MD5</B>(key,'". $_POST['uidstring'] ."') = " . PixHash($secval, $_POST['uidstring']) . "<BR /><BR />";

if ($_POST['hashtype'] == 'WIFI') {
$textval .= "
PBKDF2_WIFI_WPA2(sha1,key,'" . $_POST['uidstring'] . "',4096,256)[0:63] = " . substr(hash_pbkdf2('sha1', $secval, $_POST['uidstring'], 4096, 256),0,64) . "<BR />";
}

$textval .= "
PBKDF2_OTHER(sha256,key,$s3,10000) = " . hash_pbkdf2('sha256', $secval, $s3, 10000) . "<BR />
BCRYPT_15 = " . $bcrypth . "<BR />

";

if ($_POST['hashtype'] == '') {

$textval .= "
<BR /><BR /><span style=\"color:red;\">Note: below hashes are insecure for storing passwords.  Avoid using.</span><BR />".
//LMHash = " . LMhash($secval) . "<BR />
"
Windows_Hash = " .  NTLMHash($secval) . "<BR />
Traditional_Unix_CRYPT =  " . crypt($secval, $s0) . "<BR />
MD4 = " .  hash('md4', $secval) . "<BR />
MD5 = " . md5($secval) . "<BR />
GOST = " .  hash('gost', $secval) . "<BR />
SHA1 = " . sha1($secval) . "<BR />
SHA256 = " . sha256($secval) . "<BR />
SHA512 = " . hash('sha512', $secval) . "<BR />
RIPEMD160 = " .  hash('ripemd160', $secval) . "<BR />
<BR />
"
;
}

echo $textval0;
echo $textval;

#echo '</div></div>';

   if (empty($_POST['checkonly']) || $_POST['checkonly'] == 0) {

     if ($requestfile != '') {
   file_put_contents('d/' . $requestfile, $textval0.$textval.$textvalSec.""); // "\n\n[" . base64_encode( $secval ) . "]\n");         
     }
   file_put_contents('d/HM_'.time(), $textval0.$textval.$textvalSec.""); // "\n\n[" . base64_encode( $secval ) . "]\n");

   } else {
   file_put_contents('d/HMCO_'.time(), $textval0.$textval.$textvalSec.""); // "\n\n[" . base64_encode( $secval ) . "]\n");
   }
sleep(1);
?>








