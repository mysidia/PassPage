<?php
   /* Copyright (C) Mysidia, 2015, All Rights Reserved */
  /* utilizes 3rd party library zxcvbn.js */

   include 'config.php';
   $counter = 0;
   $countermax = 100;
   $ddeleted = 0;
   $apikey = '';
   $p_request = '';

   if (empty($apikey) &&  !empty($_GET['kc'])) {
        $apikey = $_GET['kc'];
   }

   if (!empty($_GET['request'])) {
        $p_request = $_GET['request'];
   }


   if (empty($apikey) ||  empty( $HASHMAKER_kc[$apikey] )) {
       echo '<PRE>A valid kc code or  API key is required to invoke this page.</PRE>' . "\n";
       exit(1);
   }

  if (!preg_match($VIEW_allowed_ip_regex, $_SERVER['REMOTE_ADDR'])) {
     $snip = htmlspecialchars($_SERVER['REMOTE_ADDR']);
     echo "<PRE>ERROR: This page can only be accessed from a trusted network your IP address $snip is not listed.</PRE>\n";
     exit(0);
  }
?>

  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hashmaker</title>

    <style type="text/css">
      .sh1text { color:black; font-size: 1.5em; }
      .required { color: purple; font-weight: bold; }
      .scriptlink { color: darkblue; }
      a.scriptlink:hover { background: yellow;  }

      ::-webkit-input-placeholder { /* Chrome */
        color: purple;
      }
      :-ms-input-placeholder { /* IE 10+ */
         color: purple;
      }
      ::-moz-placeholder { /* Firefox 19+ */
         color: purple;
         opacity: 1;
     }
     :-moz-placeholder { /* Firefox 4 - 18 */
         color: purple;
         opacity: 1;
    }
    </style>

    <style type="text/css">
    html,
    body {
        background-color: #39b0da;
    }
    #contents-container {
        width: 600px;
        padding-top: 5%;
    }
    </style>

    <script type="text/javascript" src="/zxcvbn.js"></script>
    <script type="text/javascript" src="/json2.js"></script>
    <script>
//var zxcvbn = require('zxcvbn');
     var resultObj;
</script>


    <!-- Bootstrap -->
    <link href="/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/all.css" rel="stylesheet">


    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <BODY CLASS="fixed-layout">
  <DIV CLASS="container" STYLE="border: solid 1px; width: 50%; margin: 10px auto; padding: 10px 10px 10px 10px;">

  <BR />
<?php if ($_GET['kc'] == "hS4sX3") { ?>
  <DIV STYLE="width: 60%;"><SPAN class="sh1text">Hashmaker with zxcvbn-c strength check</SPAN>
   <BR /><BR />
  To use,  type username and password text below, then click the button that appears<BR /> to submit for hashing.<BR />
<?php } ?>
?>
  <BR />
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <!-- <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script> -->
    <script src="/jquery.min.js"></script>
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
}



$(document).ready(function(){

if (getUrlParameter("params")) {
   var para = getUrlParameter("params");

    var idata = JSON.parse( para, function(k,v) {
               if (k == "hashtype") {   $("#hashtype").val(v);   }
               if (k == "uidstring") {   $("#uidstring").val(v);   }
               if (k == "userdata") {   $("#userdata").val(v);   }
               return v;
       } );
}

if (getUrlParameter("hashtype")) {
   $("#hashtype").val(  getUrlParameter("hashtype") )
}

if (getUrlParameter("uidstring")) {
   $("#uidstring").val(  getUrlParameter("uidstring") )
   $("#uidstring").attr('readonly', 'true');
}

if (getUrlParameter("userdata")) {
   $("#userdata").val(  getUrlParameter("userdata") )
   $("#userdatarow").hide(true);
}


<?php
######

 function myescape($p) {
    return '"' . htmlentities($p) . '"';
  }

     if (!empty($_GET['kc']) &&  !empty($HASHMAKER_kc[$_GET['kc']]) &&  !empty( $HASHMAKER_kc[$_GET['kc']]   )  ) {
           echo 'var predata = ' . json_encode($HASHMAKER_kc[$_GET['kc']]) . ';' . "\n";

           echo ' if (predata.length >= 1 && predata[0].length > 0) { $("#hashtype").val( predata[0]  ); }   ';
           echo ' $("#uidstring").val( predata[1]);    ';
           echo ' $("#userdata").val( predata[2]  );    ';
           echo ' if (predata.length > 3 && predata[3].toUpperCase() != "SOFT") {';
           echo ' $("#uidstring").attr("readonly", "true"); ';
           echo ' $("#userdatarow").hide(true); ';
           echo ' $("#udlink").hide(true); ';
           echo ' } else if ( predata.length > 3) {';
           echo ' $("#userdatarow").css("background-color", "gray"); ';
           echo ' $("#uidstringrow").css("background-color", "gray"); ';
           echo ' }';

     }
######

$HASHMAKER_kc = array(
    'DIeqsRSa' => array( 'asa', 'example', "\n" )
);

?>
<?php if ($apikey == "example_kdqwO7jvKMK4l") {  ?>
   if (getUrlParameter("uid")) {
   $("#uidstring").val(  atob(getUrlParameter("uid")) );
   $("#uidstring").attr('readonly', 'true');
   }
   $("#userdatarow").hide(true);
   $("#hashtype").val( "ASA" );
<?php } ?>



function togglePwDisplay()
{
     if ( $("#pw2hash").attr('type') == "text"  ) {
          $("#pw2hash").prop('type', 'password');
          $("#hideorshow").html("<small>[Show]</small>");
     } else {
         $("#hideorshow").html("<small>[Hide]</small>");
         $("#pw2hash").prop('type', 'text');
     }
}

function updatePwDisplay()
{
     if ( $("#pw2hash").attr('type') == "text"  ) {
         $("#hideorshow").html("<small>[Hide]</small>");
     } else {
         $("#hideorshow").html("<small>[Show]</small>");
     }
}


function toggleUd() {
  if (predata.length <= 3 || predata[3].toUpperCase() == "SOFT") {
      if ($("#userdata").css("display") == "none" )  {
             $("#userdata").show(true)
             $("#udlink").text("Hide");
      } else {
             $("#userdata").hide(true);
             $("#udlink").text("Show");
      }

  }
}

function updateUd() {
return 1;
}

$("#udlink").click(function() {
   toggleUd();
   updateUd();
});

$("#hideorshow").click(function() {
    togglePwDisplay();
    updateGauge(0);
});

$("#hideorshow").mouseup(function() {
    togglePwDisplay();
    updateGauge(0);
});


function udataArray() {
   var arr1 = $("#userdata").val().toLowerCase().split("\n");
   var arr2 = $("#userdata").val().toLowerCase().split(/(\s+)/);
   var arr1p = $("#uidstring").val().toLowerCase().split(/(\s+)/);
   var arr3 = [];
   var arr0 = [];

   var dict2 = "example\ncorrecthorsebatterystaple\n";

   arr3.push.apply(arr3, arr0);
   arr3.push.apply(arr3, dict2.toLowerCase().split("\n") );
   arr3.push.apply(arr3, dict2.toLowerCase().split("/(\s+)/") );
   arr3.push.apply(arr3, arr1);
   arr3.push.apply(arr3, arr2);
   arr3.push.apply(arr3, arr1p);
   return arr3;
//userdata
}


function updateGauge(cval) {
     updatePwDisplay();
     var scoreVal;

     $("#pw2hash").css("background-color", "none");
     if (cval == 1) {
     $("#resultdiv").hide(true);
     }
     $("#dohash").prop("disabled",true);
     $("#dohash").hide(true);
     $("#note1").html("");
     $("#note2").html("");
     $("#pw2ss").html("");


//    $zxcvbn = new Zxcvbn();
//    $resultObj = $zxcvbn->passwordStrength( $("#pw2hash").val(),  'mikra1' );

     var resultObj = zxcvbn( $("#pw2hash").val(), udataArray() );
     var scoreVal = resultObj.score;
     var x =  (100 * scoreVal) / 4;

     if ($("#uidstring").val().length <= 3 ) {
          scoreVal = 0;
     }

     $("#pw2ss").html("" + scoreVal + " of required 4  (" + x + "%)" );

     nclassName = "progress-bar-danger";
     if ( x > 40 ) { 
         nclassName = "progress-bar-warning";
     }

     if ( x > 80 ) {
         nclassName = "progress-bar-info";
     }

     if ( x > 99 ) {
         nclassName = "progress-bar-success"
     }


     $("#prog1").html('<div class="progress-bar ' + nclassName + '" id="prog1bar" role="progressbar" aria-valuenow="' + x + '" aria-valuemin="0" aria-valuemax="100" style="width:' + x + '%"> <span class="sr-only">' + x + '% Complete</span></div>');




     if (scoreVal <= 2 ) {
          $("#resultdiv").hide(true);
          $("#pw2hash").css("background-color", "red");
          $("#dohash").prop("disabled",true);
          $("#dohash").hide(true);
          $("#note1").html(resultObj.feedback.warning);

          if ($("#uidstring").val().length <= 3) {
               $("#note1").append("<br />Username is too short.");
          }

          if ($("#pw2hash").val().length >= 12 && $("#hashtype").val == "ASA") {
               $("#note1").append("<br />Long password: If using PIX-MD5 hash, Cisco PIX may reject.");
          }


          if ( $("#pw2hash").val().length > 0 ) { 
          if (resultObj.feedback.suggestions.length > 0 ) {
               $("#note2").append("<br /><small>Suggestions: </small><br />");
          }
          for(s in resultObj.feedback.suggestions) {
             $("#note2").append("<small>* " + resultObj.feedback.suggestions[s] + "</small><br />");
          }
          }
     } else if (scoreVal < 4 ) {
          $("#resultdiv").hide(true);
          $("#pw2hash").css("background-color", "yellow");
          $("#dohash").prop("disabled",true);
          $("#dohash").hide(true);
          $("#note1").html(resultObj.feedback.warning);

          if ( $("#pw2hash").val().length > 0 ) { 

          if ($("#pw2hash").val().length >= 12 && $("#hashtype").val == "ASA") {
               $("#note1").append("<br />Long password: If using PIX-MD5 hash, Cisco PIX may reject.");
          }
     
          if (resultObj.feedback.suggestions.length > 0 ) {
               $("#note2").append("<br /><small>Suggestions: </small><br />");
          }
          for(s in resultObj.feedback.suggestions) {
             $("#note2").append("<small>* " + resultObj.feedback.suggestions[s] + "</small><br />");
          }
          }

     } else { 
          $("#pw2hash").css("background-color", "green");
          $("#dohash").prop("disabled",false);
          $("#dohash").show(false);
          $("#note1").html("OK");
          if ($("#pw2hash").val().length >= 12 && $("#hashtype").val == "ASA") {
               $("#note1").append("<br />Long password: If using PIX-MD5 hash, Cisco PIX may reject.");
          }

     }


/*OVERRIDE*/
     if (scoreVal >= 4) {
          $("#checkonly").val(0);
          if (getUrlParameter("request") == null) {
              $("#dohash").val("Check and Hash");
          } else {
              $("#dohash").val("Check and Send Request");
          }
          $("#dohash").prop("disabled",false);
          $("#dohash").show(true);
     }
     else if (scoreVal >= 1) {
          $("#checkonly").val(1);

          if (getUrlParameter("request") == null) {
          $("#dohash").val("Too weak, Check Only");
          $("#dohash").prop("disabled",false);
          } else {
          $("#dohash").val("Password Too Weak, Check Only");
          $("#dohash").prop("disabled",false);
          }
          $("#dohash").show(true);
          $("#resultdiv").show(true);
     } 
     else {
          $("#checkonly").val(1);
     }
}



$("#pw2hash").keydown(function() {
   updateGauge(0);
});


$("#pw2hash").keyup(function() {
   updateGauge(0);
});

$("#uidstring").keyup(function() {
   updateGauge(0);
});


$("#uidstring").change(function() {
   updateGauge(1);
});

$("#userdata").keyup(function() {
   updateGauge(0);
});


$("#userdata").change(function() {
   updateGauge(1);
});

$("#pw2hash").change(function() {
   updateGauge(1);
});
updateGauge(1);


 $("#dohash").click(function(e) {
  e.preventDefault();

  pwval = $("#pw2hash").val();
  $("#resultdiv").show(true);
  $("#resultdiv").html("Waiting for server response...");

  if ( 1 ) {
       var mykc = <?php echo json_encode( $_GET['kc'] ); ?>;

       $.ajax( {
	         type: "POST",
			 url: "runhash.php",
			 data: { kc: mykc, checkonly: $("#checkonly").val(), hashtype : $("#hashtype").val(), uidstring: $("#uidstring").val(), pw2hash: pwval, f: getUrlParameter("f"), k: getUrlParameter("k"),  request: getUrlParameter("request") },
			 success: function(ans) { $("#resultdiv").html(ans); },
                         /*xhr: function() {
                             var xhr = $.ajaxSettings.xhr();

                             xhr.addEventListener("progress" , function(evt){
                               $('#resultdiv').html(xhr.responseText);
                             });
                             return xhr;
                         },*/
			 error: function(ans) { $("#resultdiv").html("Request failed"); }
	       } );
  }
 });

});


<?php
              print 'window.onpageshow = function(evt) { if (evt.persisted) { document.body.style.display = "none"; location.reload(); } };</SCRIPT>';

?>


<BR />
<TABLE BORDER="2" STYLE="margin-left: 10px;">
 <TR ID="userdatarow">
 <TH>Extra User dictionary:</TH>
 <TD>[<A HREF="#" ID="udlink" class="scriptlink">Open</A>] <TEXTAREA STYLE="display:none" ID="userdata" ROWS="6" COLS="80" PLACEHOLDER="Type one entry per line to augment dictionary.  should Include: First name, Last name, Full Name, E-mail Address list"></TEXTAREA></TD>
 </TR>
 <TR ID="uidstringrow">
  <TH>Username <SPAN CLASS="required">*</SPAN></TH>
  <TD><INPUT NAME="uidstring" ID="uidstring" VALUE="" PLACEHOLDER="Login name or SSID"></TD>
 </TR>
 <TR>
 <TH>Password string: <SPAN CLASS="required">*</SPAN></TH>
 <TD ID="pw2td"><INPUT TYPE="hidden" ID="checkonly" VALUE="0"><INPUT TYPE="password" ID="pw2hash" PLACEHOLDER="[Type password here ...]" COLSPAN="2"> <A HREF="#" ID="hideorshow" class="scriptlink"></TD>
 </TR>
 <TR><TD>Approximate password strength:</TD><TD><SPAN ID="pw2ss"><BR /></SPAN><BR /><SPAN ID="note1"></SPAN><BR /><SPAN ID="note2"></SPAN></TD></TR>
<TR><TD></TD><TD>
<div class="progress" style="width: 50%;" id="prog1">
  <div class="progress-bar" role="progressbar" id="prog1bar" aria-valuenow="0"
  aria-valuemin="0" aria-valuemax="100" style="width:0%">
    <span class="sr-only">0% Complete</span>
  </div>
</div>
 </TD>
 </TR>
 <TR STYLE="<?php if ($apikey == "example_afNz2OaDR0g0S") { echo "display: none;"; } ?>">
    <TH>Hash Mode</TH>
    <TD><SELECT ID="hashtype"><OPTION VALUE="">Standard Mode</OPTION><OPTION VALUE="SECURE">Secure Mode (Strong salted stretch-keyed hashes Only)</OPTION><OPTION VALUE="ASA">Cisco ASA  PIX-MD5</OPTION><OPTION VALUE="WIFI">Calculate Wi-Fi WPA2 Key derivation (RFC2898)</OPTION></SELECT><BR /> <small>Select special hashes to use</small></TD>
 </TR>
 <TR><TD></TD><TD><INPUT TYPE="button" CLASS="btn btn-primary" VALUE="Check and Submit" ID="dohash" DISABLED /><BR></TD><TD></TD></TR>
</TABLE>
<DIV ID="resultdiv" STYLE="display: none;">
</DIV>

</DIV>
</BODY>

