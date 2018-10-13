<?php
// AngelsGate V.1 Main class library by NIMIX3
// https://github.com/nimix3/AngelsGate
// 2018-2019

class AngelsGate
{
	use IPController;
	use HashController;
	use TokenController;
	use ChainController;
	use RouteController;
	use ExchangeController;
	use SignalController;
	use IdentifierController;
	
	public $Request;
	public $DataRaw;
	public $Data;
	public $Deviceid;
	public $Ssalt;
	public $Time;
	public $Seq;
	public $Config;
	public $Signature;
	public $Token;
	public $Chain;
	public $IP;
	public $Date;
	public $Identifier;
	public $isForward;
	/* public $Reserved; */

	public function __construct($ConfFile='config/config.php')
	{
		try{
			if(isset($ConfFile) and !empty($ConfFile))
			{
				if(file_exists($ConfFile))
				{
					include($ConfFile);
					$this->Config = $Configurations;
					unset($Configurations);
				}
				else
				{
					include('config/config.php');
					$this->Config = $Configurations;
					unset($Configurations);
				}
			}
			else
				exit('ERROR_SERVER_FATAL');
			return;
		}
		catch(Exception $e) {
			$this->Output('ERROR_SERVER_FATAL','_GLOBAL_',true);
		}
	}

	public function Signal()
	{
		if(strtoupper($_SERVER['REQUEST_METHOD']) === 'POST')
		{
			$input = file_get_contents("php://input");
			if(isset($input) and !empty($input))
			{
				try{
					$Crypto = new Crypto();
					$input = $this->Sdec($input,$this->Config['IV'],$this->Config['KEY']);
					$input = json_decode($input,true);
					if(isset($input) and !empty($input))
					{
						try{
							$this->Identifier = $input['Identifier'];
							$this->DataRaw = $input['Data'];
							$this->Time = $input['Time'];
							$this->Signature = $input['Signature'];
							$this->IP = $_SERVER['REMOTE_ADDR'];
							$this->Date = $this->Config['Date'];
							try{
								//Entry1
								if(method_exists($this, 'ExtractSignal'))
								{
									$Resp = $this->ExtractSignal(new SQLi($this->Config),$this->Identifier);
									if(isset($Resp) and !empty($Resp))
									{
										if(isset($Resp['Deviceid'],$Resp['Token']) and !empty($Resp['Deviceid']) and !empty($Resp['Token']))
										{
											$this->Deviceid = $Resp['Deviceid'];
											$this->Token = $Resp['Token'];
											$this->DataRaw = $this->Ndec($this->DataRaw,$this->Config['IV'],$this->Config['KEY'],$this->MixFrag($this->Token,$this->Deviceid));
											if(((time() - intval($this->Time)) > intval($this->Config["TimeLimit"])) or ((intval($this->Time) - time()) > intval($this->Config["TimeLimit"])))
											{
												$this->RawOutput('-6',true);
											}
											$SigVerify = $this->MSig($this->Deviceid,$this->DataRaw,$this->Time,$this->Token);
											if($SigVerify != $this->Signature)
											{
												$this->RawOutput('-7',true);
											}
											if(method_exists($this, 'IPSControl'))
											{
												if(! $this->IPSControl(new SQLi($this->Config),$this->IP,$this->Deviceid))
												{
													$this->RawOutput('-9',true);
												}
											}
											if($this->Config['compress'])
											{
												$this->DataRaw = gzinflate($this->DataRaw);
											}
											$this->Data = $this->DeserializeObject($this->DataRaw);
											return $this;
										}
										else
										{
											$this->RawOutput('-5',true);
										}
									}
									else
									{
										$this->RawOutput('-4',true);
									}
								}
								else
								{
									$this->RawOutput('0',true);
								}
							}
							catch(Exception $ex)
							{
								$this->RawOutput('-1',true);
							}
						}
						catch(Exception $ex)
						{
							$this->RawOutput('-2',true);
						}
					}
					else
					{
						$this->RawOutput('-3',true);
					}
				}
				catch(Exception $ex){
					$this->RawOutput('-8',true);
				}
			}
		}
		exit();
	}

	public function Input($InputX=null)
	{
		if(!isset($InputX) or empty($InputX))
		{
			if(strtoupper($_SERVER['REQUEST_METHOD']) === 'POST')
				$input = file_get_contents("php://input");
			else
				$this->Output('ERROR_INPUT_INVALID','_GLOBAL_',true);
		}
		else
		{
			$this->isForward = true;
			$input = $InputX;
		}
		if(!isset($input) or empty($input))
			$this->Output('ERROR_INPUT_EMPTY','_GLOBAL_',true);
		try{
			$Crypto = new Crypto();
			$input = $this->Sdec($input,$this->Config['IV'],$this->Config['KEY']);
			$input = json_decode($input,true);
			if(isset($input) and !empty($input))
			{
				$this->Request = $input['Request'];
				$this->Signature = $input['Signature'];
				$this->Seq = $input['Seq'];
				$this->Time = $input['Time'];
				$this->Token = $input['Token'];
				$this->Ssalt = $this->RSAs($input['Ssalt'],$this->Config['Priv8Key']);
				if(isset($input['Chain']) and !empty($input['Chain']))
					$this->Chain = $this->Rdec($input['Chain'],$this->Config['IV'],$this->Config['KEY'],$this->Ssalt);
				else
					$this->Chain = $input['Chain'];
				$this->Deviceid = $this->Rdec($input['Deviceid'],$this->Config['IV'],$this->Config['KEY'],$this->Ssalt);
				$this->DataRaw = $this->Rdec($input['Data'],$this->Config['IV'],$this->Config['KEY'],$this->Ssalt);
				if($this->Config['compress'])
				{
					$this->DataRaw = gzinflate($this->DataRaw);
				}
				$this->Data = $this->DeserializeObject($this->DataRaw);
				$this->IP = $_SERVER['REMOTE_ADDR'];
				$this->Date = $this->Config['Date'];
			}
			else
			{
				$this->Output('ERROR_INPUT_INVALID','_GLOBAL_',true);
			}
		}
		catch(Exception $e)
		{
			$this->Output('ERROR_INPUT_UNKNOW','_GLOBAL_',true);
		}
		//Gate0
		if(method_exists($this, 'IPSControl'))
		{
			if(! $this->IPSControl(new SQLi($this->Config),$this->IP,$this->Deviceid,intval($this->Config["FloodLimit"])))
			{
				$this->Output('ERROR_INPUT_BLOCKED',$this->Deviceid,true);
			}
		}
		//Gate1
		if($this->Request != $this->Config["PreAuthMethod"] and $this->Request != $this->Config["PostAuthMethod"])
		{
			if(!isset($this->Request,$this->Deviceid,$this->Signature,$this->Seq,$this->Time,$this->Token,$this->Chain,$this->Ssalt,$this->IP) or empty($this->Request) or empty($this->Deviceid) or empty($this->Signature) or empty($this->Seq) or empty($this->Time) or empty($this->Token) or empty($this->Chain) or empty($this->Ssalt) or empty($this->IP))
			{
				$this->Output('ERROR_INPUT_BROKEN',$this->Deviceid,true);
			}
		}
		else
		{
			if(!isset($this->Request,$this->Deviceid,$this->Signature,$this->Seq,$this->Time,$this->Ssalt,$this->IP) or empty($this->Request) or empty($this->Deviceid) or empty($this->Signature) or empty($this->Seq) or empty($this->Time) or empty($this->Ssalt) or empty($this->IP))
			{
				$this->Output('ERROR_INPUT_BROKEN',$this->Deviceid,true);
			}
		}
		//Gate2
		$SigVerify = $this->CSig($this->Ssalt,$this->Date,$this->Request,$this->DataRaw,$this->Deviceid,$this->Token,$this->Seq,$this->Time,$this->Chain);
		if($SigVerify != $this->Signature)
		{
			$this->Output('ERROR_INPUT_CRACKED',$this->Deviceid,true);
		}
		//Gate3
		if((time() - intval($this->Time)) > intval($this->Config["TimeLimit"]) or (intval($this->Time) - time() > intval($this->Config["TimeLimit"])))
		{
			$this->Output('ERROR_INPUT_INVALIDTIME',$this->Deviceid,true);
		}
		//Gate4
		if(method_exists($this, 'HashChecker'))
		{
			if(! $this->HashChecker(new SQLi($this->Config),$this->Ssalt,$this->IP,$this->Deviceid,intval($this->Config["TimeLimit"])))
			{
				$this->Output('ERROR_INPUT_INVALIDHASH',$this->Deviceid,true);
			}
		}
		//Gate5
		if($this->Request != $this->Config["PreAuthMethod"] and $this->Request != $this->Config["PostAuthMethod"])
		{
			if(method_exists($this, 'TokenValidator'))
			{
				if(! $this->TokenValidator(new SQLi($this->Config),$this->Token,$this->Ssalt,$this->Deviceid))
				{
					$this->Output('ERROR_INPUT_INVALIDTOKEN',$this->Deviceid,true);
				}
			}
		}
		//Gate6
		if($this->Request != $this->Config["PreAuthMethod"] and $this->Request != $this->Config["PostAuthMethod"])
		{
			if(method_exists($this, 'ChainValidator'))
			{
				if(! $this->ChainValidator(new SQLi($this->Config),$this->Chain,$this->Seq,$this->Deviceid,false))
				{
					$this->Output('ERROR_INPUT_INVALIDCHAIN',$this->Deviceid,true);
				}
			}
		}
		//Window1
		if($this->Request == $this->Config["RouteMethod"])
		{
			if(method_exists($this, 'Route'))
			{
				$Rroute = $this->Route(new SQLi($this->Config),$this->Data,$this->Deviceid);
				if(!isset($Rroute) or empty($Rroute))
				{
					$this->Output('ERROR_INPUT_INVALIDROUTE',$this->Deviceid,true);
				}
				else
				{
					if(is_array($Rroute))
					{
						$this->Output($Rroute,$this->Deviceid,true);
					}
					else
					{
						$this->Output('NOTICE_DATA_EMPTY',$this->Deviceid,true);
					}
				}
			}
		}
		//Window2
		if($this->Request == $this->Config["ExchangeMethod"])
		{
			if(method_exists($this, 'Exchanger'))
			{
				if(! $this->Exchanger(new SQLi($this->Config),$this->Ssalt,$this->Data,$this->Deviceid))
				{
					$this->Output('ERROR_INPUT_INVALIDEXCHANGE',$this->Deviceid,true);
				}
				else
				{
					$this->Output('NOTICE_EXCHANGE_SET',$this->Deviceid,true);
				}
			}
		}
		//Window3
		/*if($this->Request == $this->Config["ForwardMethod"])
		{
			$Reserved = array(
			'Request' => $this->Request ,
			'Deviceid' => $this->Deviceid ,
			'Signature' => $this->Signature ,
			'Seq' => $this->Seq ,
			'Time' => $this->Time ,
			'Token' => $this->Token ,
			'Chain' => $this->Chain ,
			'Ssalt' => $this->Ssalt
			);
			$this->Reserved = $Reserved;
			$Instance = new AngelsGate();
			$inp = $Instance->Input($this->Data);
			$this->Request = $inp['Request'];
			$this->Deviceid = $inp['Deviceid'];
			$this->Signature = $inp['Signature'];
			$this->Seq = $inp['Seq'];
			$this->Time = $inp['Time'];
			$this->Token = $inp['Token'];
			$this->Chain = $inp['Chain'];
			$this->Ssalt = $inp['Ssalt'];
		}*/
		//Gate7,8,9,10,11,12 on App
		return $this;
	}
	
	private function SerializeObject($Object)
	{
		if(is_array($Object) or is_object($Object))
		{
			$Object = json_encode($Object);
		}
		return base64_encode($Object);
	}
	
	private function DeserializeObject($Object)
	{
		@ $Object = base64_decode($Object);
		if(empty($Object))
			return null;
		$DeSe = json_decode($Object,true);
		if($DeSe === null)
		{
			return $Object;
		}
		return $DeSe;
	}
	
	private function ComputeHash($text,$salt)
	{
		if(strlen($salt) % 2 == 0)
			return str_rot13(base64_encode(hash("sha256",base64_encode($text).md5($salt))));
		else
			return str_rot13(base64_encode(hash("sha256",hash('sha1',$salt).base64_encode($text))));
	}
	
	private function GenerateID($max = 8)
	{
		if(intval($max) <= 1)
			return mt_rand(0,9);
		else if(intval($max) <= 2)
			return mt_rand(0,99);
		else if(intval($max) > 11)
			return substr(substr(time(),-8).mt_rand(10000,9999999).rand(100,9999999),0,intval($max));
		else
			return substr(mt_rand(1000,999999).rand(1000,9999999).substr(mt_rand(1000,time()),-4),0,intval($max));
	}
	
	private function GenerateString($length = 20)
	{
		$chars =  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.
				'0123456789`-=~!@#$%^&*()_+,./<>?;:[]{}|';
		$str = '';
		$max = strlen($chars) - 1;
		for ($i=0; $i < $length; $i++)
			$str .= $chars[mt_rand(0, $max)];
		return $str;
	}
	
	public function Renc($Data,$IVs,$KEYs,$Ss)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->AdvEncrypt($Data,base64_encode($this->Frag($Ss,base64_decode($KEYs))),$IVs);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function Rdec($Data,$IVs,$KEYs,$Ss)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->AdvDecrypt($Data,base64_encode($this->Frag($Ss,base64_decode($KEYs))),$IVs);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function Nenc($Data,$IVs,$KEYs,$Padding)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->AdvEncrypt($Data,base64_encode($this->Frag($Padding,base64_decode($KEYs))),$IVs);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function Ndec($Data,$IVs,$KEYs,$Padding)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->AdvDecrypt($Data,base64_encode($this->Frag($Padding,base64_decode($KEYs))),$IVs);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function Senc($Data,$IVs,$KEYs)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->AdvEncrypt($Data,$KEYs,$IVs);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function Sdec($Data,$IVs,$KEYs)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->AdvDecrypt($Data,$KEYs,$IVs);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function RSAs($Ss,$PrivateKey)
	{
		try{
			$Crypto = new Crypto();
			return $Crypto->RSADecrypt($Ss,$PrivateKey);
		}
		catch(Exception $x)
		{
			return NULL;
		}
	}
	
	private function CSig($Ss,$Date,$Request,$Data,$Deviceid,$Token,$Seq,$Time,$Chain)
	{
		return $this->ComputeHash($Ss.$Date.$Request.$Data.$Deviceid.$Token.$Chain.$Seq.$Time,$Ss);
	}
	
	private function DSig($Deviceid,$Ss,$Seq)
	{
		return $this->ComputeHash($Deviceid.$Ss,$Seq);
	}
	
	private function NSig($Deviceid,$Padding,$Token)
	{
		return $this->ComputeHash($Deviceid.$Padding,$Token);
	}
	
	private function MSig($Deviceid,$Data,$Time,$Token)
	{
		return $this->ComputeHash($Deviceid.$Data.$Time,$Token);
	}
	
	private function SSig($Ss,$Date,$Request,$Data,$Extra,$Deviceid,$Token,$Seq,$Time)
	{
		return $this->ComputeHash($Ss.$Data.$Date.$Seq.$Token.$Time.$Request.$Extra.$Deviceid,$Ss);
	}
	
	private function Tokenize($Base,$Salt)
	{
		return sha1($Base.$Salt);
	}
	
	private function Frag($Base,$Addition,$Limit=16)
	{
		if(strlen($Base) < $Limit)
		{
			return substr($Base.$Addition.str_repeat("0",$Limit),0,$Limit);
		}
		else
		{
			return substr($Base,0,$Limit);
		}
	}
	
	private function MixFrag($Base,$Addition,$Limit=16)
	{
		$Pivot = intval($Limit / 2);
		if(strlen($Base) < $Pivot)
		{
			return substr($Base.$Addition.str_repeat("0",$Limit),0,$Limit);
		}
		else
		{
			return substr(substr($Base,0,$Pivot).$Addition.str_repeat("0",$Limit),0,$Limit);
		}
	}
	
	public function SyncTime()
	{
		if(isset($_REQUEST['T']))
		{
			$this->RawOutput(time(),true);
		}
	}

	public function RawOutput($data,$ex=false)
	{
		@ header('Content-type: application/json; charset=utf-8');
		@ header_remove("Server");
		@ header_remove("Content-Type");
		@ header_remove("Transfer-Encoding");
		@ header_remove("Set-Cookie");
		@ header_remove("P3P");
		@ header_remove("Date");
		@ header_remove("X-Page-Speed");
		@ header_remove("Cache-Control");
		//echo json_encode($data,JSON_UNESCAPED_UNICODE);
		echo $data;
		if($ex)
			exit();
	}
	
	public function Output($Data,$Deviceid,$ex=false,$Token=null,$Extra=null)
	{
		if(!isset($Deviceid) or empty($Deviceid))
		{
			$Deviceid = $this->Deviceid;
		}
		try{
			//Making Data
			if(isset($Data) and !empty($Data))
			{
				$Data = $this->SerializeObject($Data);
			}
			else
			{
				$Data = NULL;
			}
			$DataFinal = $this->Renc($Data,$this->Config['IV'],$this->Config['KEY'],$this->Ssalt);
			
			//Making Extra
			if(isset($Extra) and !empty($Extra))
			{
				$Extra = $this->SerializeObject($Extra);
			}
			else
			{
				$Extra = NULL;
			}
			$ExtraFinal = $this->Renc($Extra,$this->Config['IV'],$this->Config['KEY'],$this->Ssalt);
			
			//Making DeviceVerify
			/*if($this->Request != $this->Config["PreAuthMethod"])
			{
				if(method_exists($this, 'TokenFetch'))
				{
					$ownToken = $this->TokenFetch(new SQLi($this->Config),$this->Deviceid);
				}
			}
			else
			{
				$ownToken = NULL;
			}*/
			
			//Making Token
			if(method_exists($this, 'TokenGenerator'))
			{
				if(!isset($Token) or empty($Token))
				{
					if($this->Request == $this->Config["PostAuthMethod"])
					{
						$force = true;
						$set = true;
						$Token = $this->TokenGenerator(new SQLi($this->Config),NULL,$this->Deviceid,$force,$set);
						//$ownToken = $Token;
						if(method_exists($this,'setIdentifier'))
						{
							$this->setIdentifier(new SQLi($this->Config),$this->Deviceid);
						}
					}
					else
					{
						if($this->Request != $this->Config["PreAuthMethod"] and $this->Request != $this->Config["ExchangeMethod"])
							$Token = $this->TokenGenerator(new SQLi($this->Config),NULL,$this->Deviceid,false,false);
						else
							$Token = NULL;
					}
				}
				else
				{
					if($this->Request != $this->Config["PreAuthMethod"] and $this->Request != $this->Config["ExchangeMethod"])
						$Token = $this->TokenGenerator(new SQLi($this->Config),$Token,$this->Deviceid,true,false);
					else
						$Token = NULL;
				}
			}
			$TokenFinal = $this->Renc($Token,$this->Config['IV'],$this->Config['KEY'],$this->Ssalt);
			$DeviceidVerify = $this->DSig($Deviceid,$this->Ssalt,$this->Seq);
			
			//Making Seq & Time
			$Seq = $this->Seq;
			$Time = time();
			
			//Making Signature
			$Signature = $this->SSig($this->Ssalt,$this->Config['Date'],$this->Request,$Data,$Extra,$Deviceid,$Token,$Seq,$Time);
			
			//Creating Final Package
			$Pack = array(
			'Signature'=> $Signature,
			'Data'=> $DataFinal,
			'DeviceidVerify'=> $DeviceidVerify,
			'Extra'=> $ExtraFinal,
			'Seq'=> $Seq,
			'Token'=> $TokenFinal,
			'Time'=> $Time
			);
			
			//Encapsulation
			$ResPack = json_encode($Pack,JSON_UNESCAPED_UNICODE);
			
			//Final Encryption
			$ResPackFinal = $this->Senc($ResPack,$this->Config['IV'],$this->Config['KEY']);
			
			//Response Minify
			@ header_remove("Server");
			@ header_remove("Content-Type");
			@ header_remove("Transfer-Encoding");
			@ header_remove("Set-Cookie");
			@ header_remove("P3P");
			@ header_remove("Date");
			@ header_remove("X-Page-Speed");
			@ header_remove("Cache-Control");
			echo $ResPackFinal;
			/*if(isset($this->Reserved) and !empty($this->Reserved))
			{
				$this->Request = $this->Reserved['Request'];
				$this->Deviceid = $this->Reserved['Deviceid'];
				$this->Signature = $this->Reserved['Signature'];
				$this->Seq = $this->Reserved['Seq'];
				$this->Time = $this->Reserved['Time'];
				$this->Token = $this->Reserved['Token'];
				$this->Chain = $this->Reserved['Chain'];
				$this->Ssalt = $this->Reserved['Ssalt'];
				$this->Reserved = NULL;
				$this->Output($ResPackFinal,$this->Deviceid,true);
			}
			else
			{
				echo $ResPackFinal;
			}*/
			
			//Setting Chain
			if($this->Request != $this->Config["PreAuthMethod"])
			{
				if(method_exists($this, 'ChainSubmit'))
				{
					if(! $this->ChainSubmit(new SQLi($this->Config),$this->Signature,$Signature,$this->Seq,$this->Deviceid))
					{
						//Do Nothing\\
					}
				}
			}
			
			//Terminate
			if($ex)
				exit();
		}
		catch(Exception $ex)
		{
			die('ERROR_SERVER_FATAL');
		}
	}
}
?>