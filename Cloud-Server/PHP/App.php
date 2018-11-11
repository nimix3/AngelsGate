<?php
// AngelsGate V.2 App webservice by NIMIX3
// https://github.com/nimix3/AngelsGate
// 2018-2019

require_once( dirname( __FILE__ ) . '/library/CryptoEx.php' );
require_once( dirname( __FILE__ ) . '/library/SQLi.php' );
require_once( dirname( __FILE__ ) . '/library/AngelsGateExtensions.php' );
require_once( dirname( __FILE__ ) . '/library/AngelsGate.php' );
require_once( dirname( __FILE__ ) . '/library/EndPoint.php' );

$API = new GlobalApi();
$API->AngelsGate->Input();
$Func = $API->AngelsGate->Request;
//==============================Lets Play==============================//
if(method_exists($API,$Func))
{
	call_user_func(array($API,$Func));
	exit();
}
else
{
	$API->AngelsGate->Output('ERROR_INPUT_BADREQUEST',$API->AngelsGate->Deviceid,true);
	exit();
}
$API->AngelsGate->Output('ERROR_SERVER_FATAL','_GLOBAL_',true);
exit();
?>
