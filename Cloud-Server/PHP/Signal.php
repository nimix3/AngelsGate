<?php
// AngelsGate V.2 Signal webservice by NIMIX3
// https://github.com/nimix3/AngelsGate
// 2018-2019

require_once( dirname( __FILE__ ) . '/library/CryptoEx.php' );
require_once( dirname( __FILE__ ) . '/library/SQLi.php' );
require_once( dirname( __FILE__ ) . '/library/AngelsGateExtensions.php' );
require_once( dirname( __FILE__ ) . '/library/AngelsGate.php' );
require_once( dirname( __FILE__ ) . '/library/EndPoint.php' );

$API = new GlobalApi();
$API->AngelsGate->Signal();
$Func = $API->AngelsGate->Config["SignalMethod"];
//==============================Lets Play==============================//
if(method_exists($API,$Func))
{
	call_user_func(array($API,$Func));
	exit();
}
else
{
	$API->AngelsGate->RawOutput('-10',true);
	exit();
}
$API->AngelsGate->RawOutput('-11',true);
exit();
?>
