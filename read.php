<?php
   /* Copyright (C) Mysidia, 2010, All Rights Reserved */

   include 'config.php';
   $counter = 0;
   $countermax = 100;
   $ddeleted = 0;

  if (!preg_match($VIEW_allowed_ip_regex, $_SERVER['REMOTE_ADDR'])) {
     $snip = htmlspecialchars($_SERVER['REMOTE_ADDR']);
     echo "<PRE>ERROR: This page can only be accessed from a trusted network your IP address $snip is not listed.</PRE>\n";
     exit(0);
  }

   $mm = $_REQUEST['f'];
   $h1 = date("Ymd", time());
   $h2 = date("Ymd", time() - 86400);
   $h3 = date("Ymd", time() + 86400);
   #$h4 = date("Ymd", time() + 86400 + 86400);
   $viewlist = array();

   if ($mm) {
        $subject = $mm;
        $pattern = '/^[a-zA-Z0-9]+([0-9]{8})x([0-9]+)\.txt?$/';
        $z = preg_match($pattern, $subject, $matches, PREG_OFFSET_CAPTURE, 0);
 
        #print_r($matches[1]);

        if ($z == 1) { 
             $xm = $matches[1];
             $xn = $matches[2];
             $xk = empty($_REQUEST['k']) ? "" : base64_decode($_REQUEST['k']);

             $xnn = $xn[0];

             if ($xn[0] == 0) { $xnn = 86400; }

              print '<HTML>';
              print <<<END
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex, nofollow" />
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title>Viewer</title>

    <!-- Bootstrap -->
    <link href="/css/bootstrap.min.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <BODY>

    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/js/bootstrap.min.js"></script>

    <SCRIPT TYPE="text/javascript">
var getUrlParameter = function getUrlParameter(sParam) {
    var sPageURL = decodeURIComponent(window.location.search.substring(1)),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : sParameterName[1];
        }
    }
};

$(document).ready(function(){
$("#delete").click(function(e) {
  e.preventDefault();

  if ( confirm("Are you sure?") ) {
       $.ajax( {
	         type: "POST",
			 url: "a.php",
			 data: { f: getUrlParameter("f"), k: getUrlParameter("k"), d: "Delete Now" },
			 success: function(ans) { document.body.innerHTML = ans; },
			 error: function(ans) { alert("Deletion failed"); }
	       } );
  }});

});


END;
              print 'window.onpageshow = function(evt) { if (evt.persisted) { document.body.style.display = "none"; location.reload(); } };</SCRIPT>';

             $doctime_s = strptime($xm[0], "%Y%m%d");
             $doctime = mktime(0,0,0,$doctime_s['tm_mon']+1,$doctime_s['tm_mday'],$doctime_s['tm_year']+1900);

	     if (($doctime < 1527178665) && ($xnn >= 86400)) {
		 $xnn += 86400 * 15;
	     }
             if ($doctime == 1594098000) {
                 $xnn += 86400 * 11;
             }

             #if ($xm[0] == $h1 || $xm[0] == $h2 || $xm[0] == $h3 || $xm[0] == $h3) { 

             if (($xnn == 1) || time() < ($doctime + $xnn) ) {
                 $mystring = file_get_contents('d/'.$subject);
                 $metastr = file_get_contents('d/'.$subject . '.meta');
                 $metarows = explode("\n", $metastr);
                 foreach ($metarows as $mrow) {
                       $aitem = explode(" ", $mrow);
                       if (!empty($aitem) && !empty($aitem[0]) && !empty($aitem[1])) {
                          if ($aitem[0] == "counter" && $xnn != 1) {
                               $counter = intval($aitem[1]); 
                          } 
                          if ($aitem[0] == "countermax" && $xnn !=1) {
                               $countermax = intval($aitem[1]); 
                               if ($countermax > 100 || ( $countermax < 1 && $countermax != -2 )) { $countermax = 100; }
                          } 
                          if ($aitem[0] == "ddeleted") {
                               $ddeleted = intval($aitem[1]);
                          }
                          if ($aitem[0] == "viewlist") {
                               array_push($viewlist, base64_decode($aitem[1]));
                          }
                       }
                 }

                 if (!empty($_REQUEST['d'])) {
                     $ddeleted = 1;
                     array_push($viewlist, ("deleted by " . $_SERVER['REMOTE_ADDR'] . "; " . date("Y-m-d H:i:s")  ));
                     $newmeta = "ddeleted ${ddeleted}\ncountermax ${countermax}\ncounter ${counter}\n";
                     foreach ($viewlist as $vli) {
                            $newmeta .= "viewlist " . base64_encode($vli) . "\n";
                     }
                     file_put_contents('d/'.$subject . '.meta',  $newmeta);
                 }


                 if (!empty($_SERVER['HTTP_REFERER']) && strpos($_SERVER['HTTP_REFERER'], '/c.php')) {
                     print '<H4>Encrypted 3DES Using random key: ' . htmlspecialchars($_REQUEST['k']) . '</H4>';
                     print '<H4>Access Link: ' . $VIEW_baseurl  . $_REQUEST['f']  . '&k=' . $_REQUEST['k'] . '</H4>';
                     if ($xnn == 1){
                     print '<H4>SHA256(b64_ciphertext): ' . sha256($mystring) . '</H4>';
                     }
                     print '<HR>';
                 }


                 if ($xnn == 1) {
                      print '<H4>Stored artifact created ' . ' ' . date("Ymd", ( $doctime  )) . ' flags=permanent</H4>';
                 } else if ($countermax != -2) {
                 print '<H4>This document expires after ' . ' ' . date("Ymd", ( $doctime + $xnn  )) . ' or after ' . ($countermax-$counter - 1) . ' more viewings'  . '</H4>';
                } else {
                 print '<H4>This document expires after ' . ' ' . date("Ymd", ( $doctime + $xnn  )) . ' or after &infin;  more viewings'  . '</H4>';
                }

                 if (($countermax != -2 && $counter >= $countermax) || $ddeleted == 1) {
                      print "<H2>Error: This link was purged.</H2>\n";
                      if ($xnn != 1) {
                      echo "This document was viewed ${counter} out of ${countermax} times<br>\n\n";
                      } else {
                      echo "This document was viewed ${counter} out of &infin; times<br>\n\n";
                      }
                      foreach($viewlist as $vli) {
                           echo "     " . htmlspecialchars( $vli ) . "<br>\n";
                      }
                      echo "<br>\n";
                 } elseif ($xk == "" || empty($xk)) { 
                     print $mystring;
                     $mystring = "";

                    $counter = $counter + 1;
                    array_push($viewlist, ("viewed by " . $_SERVER['REMOTE_ADDR'] . "; " . date("Y-m-d H:i:s")  ));

                     foreach ($viewlist as $vli) {
                            $newmeta .= "viewlist " . base64_encode($vli) . "\n";
                     }
                    $newmeta = "ddeleted ${ddeleted}\ncountermax ${countermax}\ncounter ${counter}\n";
                    file_put_contents('d/' . $subject . '.meta',  $newmeta);

                    echo "<br>\n\n";
                    if ($xnn != 1) { 
                         echo "This link has been viewed ${counter} out of ${countermax} times\n";
                    } else {
                         echo "This link has been viewed ${counter} out of &infin; times\n";
                    }
                    #echo '<FORM METHOD="post"><INPUT TYPE="Submit" NAME="d" VALUE="Delete Now"></FORM>';
                 } else {
                      $td = mcrypt_module_open("tripledes","","ecb","");
                      mcrypt_generic_init($td, $xk, "00000000");
                      print mdecrypt_generic($td, base64_decode($mystring));

                      $mystring = "";
                      mcrypt_generic_deinit($td);

                     $counter = $counter + 1;
                     array_push($viewlist, ("viewed by " . $_SERVER['REMOTE_ADDR'] . "; " . date("Y-m-d H:i:s")  ));
                     $newmeta = "ddeleted ${ddeleted}\ncountermax ${countermax}\ncounter ${counter}\n";
                     foreach ($viewlist as $vli) {
                            $newmeta .= "viewlist " . base64_encode($vli) . "\n";
                     }

                     file_put_contents('d/'.$subject . '.meta',  $newmeta);

                    if ($xnn != 1) {
                    echo "This document has been viewed ${counter} out of ${countermax} times<br>\n\n";
                    } else {
                    echo "This document has been viewed ${counter} out of &infin; times<br>\n\n";
                    }

                    foreach($viewlist as $vli) {
                        echo "     " . htmlspecialchars( $vli ) . "<br>\n";
                    }

                    if ($xnn != 1) {
                    echo '<FORM METHOD="post"><INPUT TYPE="Hidden" NAME="f" VALUE="' . $subject . '"><INPUT TYPE="Submit" ID="delete" NAME="d" VALUE="Delete Now" ' .  ( ($countermax==-2) ? " style=\"display:none\" " : "" ) . '></FORM>';
                    }
                 }
                 print '</P>';
             } else { 
                 print "<H2>Error: Link has expired.</H2>\n";
             }


             print '</HTML></BODY>';
        }
   }
?>
