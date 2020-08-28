<?php
  date_default_timezone_set('America/Chicago');
  include 'config.php';


  if (!preg_match($CREDSEND_allowed_ip_regex, $_SERVER['REMOTE_ADDR'])) {
     $snip = htmlspecialchars($_SERVER['REMOTE_ADDR']);
     echo "<PRE>ERROR: This page can only be accessed from a trusted network your IP address $snip is not listed.</PRE>\n";
     exit(0);
  }

  $recipient = $DEFAULT_recipient;
  $recname = '';
  $found = 0;

  if (empty($_GET['kc'])) {
     echo "<PRE>ERROR: Invalid Key</PRE>\n";
     exit(0);
  }

  $kcval = $_GET['kc'];

  if ( array_key_exists($kcval, $CODED_recipients) && $CODED_recipients[ $kcval  ] ) {
       $recname = $CODED_recipients[$kcval][1];
       $recipient = $CODED_recipients[$kcval][0];
       $found = 1;
  }





  if ($found == 0) {
     echo "<PRE>ERROR: Invalid Key</PRE>\n";
     exit(0);
  }

  $countermax = 1000;

  function rand_sha1($length) {
      $max = ceil($length / 40);
      $random = '';
      for ($i = 0; $i < $max; $i ++) {
       $random .= sha1(microtime(true).mt_rand(10000,90000));
      }
      return substr($random, 0, $length);
   }

  if (!empty($_POST['c']) && !empty($_POST['c'])) {
   $h1 = date("Ymd", time());
   $ranstring = rand_sha1(10);
   $rankey = rand_sha1(24);

   $config = array(
    "digest_alg" => "sha512",
    "private_key_bits" => 4096,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
   );
   $res = openssl_pkey_new($config);
   openssl_pkey_export($res, $privKey);

   if (!empty($_POST['countermax'])) {
        $countermax = intval($_POST['countermax']);
   }


   $putdata = '';
   $putdata .= "<PRE>\n";
   $putdata .= "Body:   \n";
   $putdata .= htmlspecialchars($_POST['message']) . "\n";
   $putdata .= "</PRE>\n";
   $e = 86400 * 365 * 2;
   if (!empty($_POST['expire'])) {
        $e = 86400 * intval($_POST['expire']);
        if ($e < 86400) { $e = 86400; }
   }
   $o = "${ranstring}${h1}x${e}.txt";
   #_K${rankey}";

   file_put_contents('d/'.$o.'.meta', "countermax {$countermax}\ncounter 0\n" .
         "viewlist " . base64_encode("\nthis link created by " . $_SERVER['REMOTE_ADDR'] . "; " . date("Y-m-d H:i:s") . "\n") . "\n");


   $td = mcrypt_module_open("tripledes","","ecb","");
   mcrypt_generic_init($td, $rankey, "00000000");
   $putdata = base64_encode( mcrypt_generic($td, $putdata) );
   mcrypt_generic_deinit($td);


   #$putdata = base64_encode( mcrypt_ecb(MCRYPT_DES, $rankey, $putdata, MCRYPT_ENCRYPT) ); 

   file_put_contents('d/'.$o, $putdata);


  ini_set("sendmail_from",  $CRED_sender);

   mail($recipient, 'Data submission ', $VIEW_baseurl . $o . '&k=' . base64_encode($rankey), 'From: <' . $CRED_sender . '>\r\n', '-f' . $CRED_sender);

   syslog( LOG_NOTICE,  'Sent link to '  . $VIEW_baseurl . $o . '&k=' . base64_encode($rankey) );
   echo 'Link to submission has been sent to ' . $CRED_sender . '<BR><BR>'; 
   echo '<PRE>' . htmlspecialchars($_POST['message']) . '</PRE>';


  } else {
?>
    <BODY><DIV style="border: solid 1px; width: 60%; padding: 50px 50px 50px 50px;"><FORM METHOD="POST" ACTION="sub2.php?kc=<?php echo $_GET['kc'];   ?>">
      <INPUT TYPE="HIDDEN" NAME="c" VALUE="1" />
       Recipient: <?php echo $recname; ?>
      <BR>
      <P>Enter data to send</P>
      <TEXTAREA NAME="message" rows="15" cols="80"></TEXTAREA><BR><BR>
      <INPUT TYPE="submit" value="Submit and View" /></FORM>
     </DIV>
    </BODY>
<?php
  }
?>
