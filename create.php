<?php
   /* Copyright (C) Mysidia, 2010, All Rights Reserved */

  include 'config.php';
  require 'random_compat/lib/random.php';

  if (!preg_match($CREATE_allowed_ip_regex, $_SERVER['REMOTE_ADDR'])) {
     $snip = htmlspecialchars($_SERVER['REMOTE_ADDR']);
     echo "<PRE>ERROR: This page can only be accessed from a trusted network your IP address $snip is not listed.</PRE>\n";    
     exit(0);
  }

  date_default_timezone_set('US/Central');
  $countermax = 100;

  function rand_sha1($length) {
      $max = ceil($length / 40);
      $random = '';
      for ($i = 0; $i < $max; $i ++) {
       #$random .= sha1(microtime(true).mt_rand(10000,90000));
        $random .= sha1( random_bytes(10)  );
      }
      #$random = sha1(random_bytes($length));
      return substr($random, 0, $length);
   }

  if (!empty($_POST['c']) && !empty($_POST['c'])) {
   $h1 = date("Ymd", time());
   $ranstring = rand_sha1(10);
   $rankey = rand_sha1(24);

   #$config = array(
   # "digest_alg" => "sha512",
   # "private_key_bits" => 4096,
   # "private_key_type" => OPENSSL_KEYTYPE_RSA,
   #);
   #$res = openssl_pkey_new($config);
   #openssl_pkey_export($res, $privKey);
   #
   if (!empty($_POST['countermax'])) {
        $countermax = intval($_POST['countermax']);
   }

   $putdata = '';
   $putdata .= "<PRE>\n";
   $putdata .= "Body:   \n";
   $putdata .= htmlspecialchars($_POST['message']) . "\n";
   $putdata .= "</PRE>";
   //$putdata .= "<!-- " . sha256(time() . "_X" . htmlspecialchars(var_export($_SERVER,true)) . "X_" ) . " -->\n";
   $e = 86400;
   if (!empty($_POST['expire'])) {
        $e = 86400 * intval($_POST['expire']);
        if ($e < 86400) { $e = 86400; }
   }
   if ($_POST['expire'] == 'artifact') {
        $e = 1; #'permanent';
        $countermax = -2;
   }
   $o = "${ranstring}${h1}x${e}.txt";
   #_K${rankey}";

   file_put_contents('d/'.$o.'.meta', "countermax {$countermax}\ncounter 0\ntimes {$h1} {$e}\n" .
         "viewlist " . base64_encode("\nthis link created by " . $_SERVER['REMOTE_ADDR'] . "; " . date("Y-m-d H:i:s") . " dochash=" . sha256($putdata)  ."\n") . "\n");


   $td = mcrypt_module_open("tripledes","","ecb","");
   mcrypt_generic_init($td, $rankey, "00000000");
   $putdata = base64_encode( mcrypt_generic($td, $putdata) );
   mcrypt_generic_deinit($td);


   #$putdata = base64_encode( mcrypt_ecb(MCRYPT_DES, $rankey, $putdata, MCRYPT_ENCRYPT) ); 

   file_put_contents('d/'.$o, $putdata);

   if (!empty($_POST['printloc22'])) {
         echo $VIEW_baseurl . $o . '&k=' . base64_encode($rankey) . "\n";
         exit(0);
   }
   header('Location: ' . $VIEW_baseurl . $o . '&k=' . base64_encode($rankey));
   echo "O";
  } else {
?>
    <BODY><DIV style="border: solid 1px; width: 20%; padding: 50px 50px 50px 50px;"><FORM METHOD="POST" ACTION="c.php">
      <INPUT TYPE="HIDDEN" NAME="c" VALUE="1" />
      Link will expire in <INPUT TYPE="text" name="expire" value="1" /> day(s)<BR>
      Link will expire after <INPUT TYPE="text" name="countermax" value="10" /> view(s)<BR><BR>
      <B>Warning:</B> After given number of days or views, it will be rendered unreadable.
      <BR>
      <BR>
      <P>Enter credentials to send</P>
      <TEXTAREA NAME="message" rows="5" cols="40"></TEXTAREA><BR><BR>
      <INPUT TYPE="submit" value="Submit and View" /></FORM>
     </DIV>
    </BODY>
<?php
  }
?>
