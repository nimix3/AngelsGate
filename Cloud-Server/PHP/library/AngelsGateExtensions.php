<?php
// AngelsGate V.2 Extension class library by NIMIX3
// https://github.com/nimix3/AngelsGate
// 2018-2019

trait IPController
{
	public function IPSControl($SQL,$IP,$Deviceid,$MaxPermit=30)
	{
		if(!isset($SQL,$IP,$Deviceid) or empty($SQL) or empty($IP) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$IP = $SQL->SecureDBQuery($IP,true);
			$resx = $SQL->SelectDBsecure('*','IPTable','ip','=','?',array($IP));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(intval($resx[0]['block']) > time())
				{
					return false;
				}
				else
				{
					if(intval($resx[0]['time']) == time())
					{
						if($resx[0]['count'] >= intval($MaxPermit))
						{
							$SQL->UpdateDBsecure('IPTable','ip','=','?',array($IP),array('time'=>time(),'count'=>intval($resx[0]['count'])+1,'total'=>intval($resx[0]['total'])+1,'block'=>time() + 300),1);
							return false;
						}
						else
						{
							$SQL->UpdateDBsecure('IPTable','ip','=','?',array($IP),array('time'=>time(),'count'=>intval($resx[0]['count'])+1,'total'=>intval($resx[0]['total'])+1),1);
							return true;
						}
					}
					else
					{
						$SQL->UpdateDBsecure('IPTable','ip','=','?',array($IP),array('time'=>time(),'count'=>1,'total'=>intval($resx[0]['total'])+1),1);
						return true;
					}
				}
			}
			else
			{
				$SQL->InsertDBsecure('IPTable',array('ip'=>$IP,'time'=>time(),'count'=>1,'total'=>1,'block'=>0));
				return true;
			}
		}
		else
		{
			return false;
		}
	}
}

trait HashController
{
	public function HashChecker($SQL,$Ssalt,$IP,$Deviceid,$timelimit=86400)
	{
		if(!isset($SQL,$Ssalt,$Deviceid,$IP) or empty($SQL) or empty($Ssalt) or empty($Deviceid) or empty($IP))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$Ssalt = $SQL->SecureDBQuery($Ssalt,true);
			$IP = $SQL->SecureDBQuery($IP,true);
			$resx = $SQL->SelectDBsecure('*','HashTable','session','=','? AND `ssalt` = ?',array($Deviceid,$Ssalt));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(intval($resx[0]['time']) + intval($timelimit) >= time())
				{
					return false;
				}
				else
				{
					$SQL->UpdateDBsecure('HashTable','session','=','? AND `ssalt` = ?',array($Deviceid,$Ssalt),array('time'=>time(),'ip'=>$IP),1);
					return true;
				}
			}
			else
			{
				$SQL->InsertDBsecure('HashTable',array('ssalt'=>$Ssalt,'time'=>time(),'ip'=>$IP,'session'=>$Deviceid));
				return true;
			}
		}
		else
		{
			return false;
		}
	}
}

trait TokenController
{
	public function TokenValidator($SQL,$Token,$Ssalt,$Deviceid)
	{
		if(!isset($SQL,$Token,$Deviceid,$Ssalt) or empty($SQL) or empty($Ssalt) or empty($Token) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$Token = $SQL->SecureDBQuery($Token,true);
			$Ssalt = $SQL->SecureDBQuery($Ssalt,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(sha1($resx[0]['token'].$Ssalt) == $Token)
				{
					return true;
				}
				else
				{
					if(sha1($resx[0]['cantoken'].$Ssalt) == $Token)
					{
						return true;
					}
					else
					{
						//$SQL->DeleteDBsecure('AuthTable','session','=','?',array($Deviceid),1);
						return false;
					}
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	
	public function TokenGenerator($SQL,$Token,$Deviceid,$force=false,$set=false,$regentime=864000)
	{
		if(!isset($SQL,$Deviceid) or empty($SQL) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if($force)
				{
					if(isset($Token) and !empty($Token))
					{
						$newToken = $Token;
					}
					else
					{
						$newToken = $this->GenerateString(20);
					}
					if($set)
						$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('cantoken'=>NULL,'token'=>$newToken,'timetoken'=>time(),'time'=>time()),1);
					else
						$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('cantoken'=>$newToken,'timetoken'=>time(),'time'=>time()),1);
					return $newToken;
				}
				else if(intval($resx[0]['timetoken']) + intval($regentime) < time())
				{
					if(isset($Token) and !empty($Token))
					{
						$newToken = $Token;
					}
					else
					{
						$newToken = $this->GenerateString(20);
					}
					$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('cantoken'=>$newToken,'timetoken'=>time(),'time'=>time()),1);
					return $newToken;
				}
				else
				{
					if(isset($resx[0]['cantoken']) and !empty($resx[0]['cantoken']))
					{
						return $resx[0]['cantoken'];
					}
					else
					{
						return NULL;
					}
				}
			}
			else
			{
				return NULL;
			}
		}
		else
		{
			return NULL;
		}
	}
	
	public function TokenFetch($SQL,$Deviceid)
	{
		if(!isset($SQL,$Deviceid) or empty($SQL) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(isset($resx[0]['token']) and !empty($resx[0]['token']))
				{
					return $resx[0]['token'];
				}
				else
				{
					return NULL;
				}
			}
			else
			{
				return NULL;
			}
		}
		else
		{
			return NULL;
		}
	}
	
	public function GenerateString($length = 20)
	{
		$chars =  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.
				'0123456789`-=~!@#$%^&*()_+,./<>?;:[]{}|';
		$str = '';
		$max = strlen($chars) - 1;
		for ($i=0; $i < $length; $i++)
			$str .= $chars[mt_rand(0, $max)];
		return $str;
	}
}

trait IdentifierController
{
	public function setIdentifier($SQL,$Deviceid)
	{
		if(!isset($SQL,$Deviceid) or empty($SQL) or empty($Deviceid))
			return 0;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				$Identifier = $this->ComputeHash($Deviceid,$resx[0]['token']);
				$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('identifier'=>$Identifier,'time'=>time()),1);
				return 1;
			}
			else
			{
				return -1;
			}
		}
		else
		{
			return 0;
		}
	}
	
	private function ComputeHash($text,$salt)
	{
		if(strlen($salt) % 2 == 0)
			return str_rot13(base64_encode(hash("sha256",base64_encode($text).md5($salt))));
		else
			return str_rot13(base64_encode(hash("sha256",hash('sha1',$salt).base64_encode($text))));
	}
}

trait ChainController
{
	public function ChainValidator($SQL,$Chain,$Seq,$Deviceid,$Restrict=false,$rlimit=300,$countlimit=100)
	{
		if(!isset($SQL,$Chain,$Deviceid,$Seq) or empty($Seq) or empty($SQL) or empty($Chain) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$Chain = $SQL->SecureDBQuery($Chain,true);
			$Seq = $SQL->SecureDBQuery($Seq,true);
			@ $ChainArr = explode(",,,",$Chain);
			if(empty($ChainArr) or !is_array($ChainArr))
				return false;
			$ReqC = $ChainArr[0];
			$ResC = $ChainArr[1];
			if(!isset($ReqC,$ResC) or empty($ReqC) or empty($ResC))
				return false;
			$resx = $SQL->SelectDBsecure('*','ChainTable','session','=','? AND (`req` = ? OR `res` = ?) ORDER BY `time` DESC',array($Deviceid,$ReqC,$ResC),100);
			if(isset($resx[0]) and !empty($resx[0]))
			{
				$res = $SQL->DeleteDBsecure('ChainTable','session','=','? AND `rlimit` > ? AND `rlimit` < ?',array($Deviceid,0,time()),999999);
				$SQL->UpdateDBsecure('ChainTable','(`time`','<','? OR `id` < ?) AND `session` = ? AND `rlimit` = ?',array($resx[0]['time'],$resx[0]['id'],$Deviceid,0),array('rlimit'=>intval(time()+intval($rlimit))),999999);
				if((intval($resx[0]['rlimit']) > 0 and intval($resx[0]['rlimit']) < time()) or $resx[0]['count'] > intval($countlimit))
				{
					if($Restrict)
					{
						$SQL->DeleteDBsecure('ChainTable','session','=','?',array($Deviceid),999999);
						$SQL->DeleteDBsecure('AuthTable','session','=','?',array($Deviceid),999999);
					}
					return false;
				}
				else
				{
					$SQL->UpdateDBsecure('ChainTable','id','=','? AND `session` = ?',array($resx[0]['id'],$Deviceid),array('count'=>intval($resx[0]['count']+1)),1);
					return true;
				}
			}
			else
			{
				if($Restrict)
				{
					$SQL->DeleteDBsecure('ChainTable','session','=','?',array($Deviceid),999999);
					$SQL->DeleteDBsecure('AuthTable','session','=','?',array($Deviceid),999999);
				}
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	
	public function ChainSubmit($SQL,$Req,$Res,$Seq,$Deviceid)
	{
		if(!isset($SQL,$Req,$Res,$Seq,$Deviceid) or empty($Seq) or empty($SQL) or empty($Res) or empty($Req) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$Req = $SQL->SecureDBQuery($Req,true);
			$Res = $SQL->SecureDBQuery($Res,true);
			$Seq = $SQL->SecureDBQuery($Seq,true);
			$SQL->InsertDBsecure('ChainTable',array('session'=>$Deviceid,'req'=>$Req,'res'=>$Res,'count'=>1,'time'=>time(),'rlimit'=>0,'seq'=>$Seq));
			return true;
		}
		else
		{
			return false;
		}
	}
}

trait RouteController
{
	public function Route($SQL,$Data,$Deviceid)
	{
		if(!isset($SQL,$Deviceid,$Data) or empty($Data) or empty($SQL) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(isset($Data) and !empty($Data))
				{
					if(isset($Data['label'],$Data['endpoint'],$Data['pubkey'],$Data['myid']) and !empty($Data['myid']) and !empty($Data['pubkey']) and !empty($Data['endpoint']) and !empty($Data['label']))
					{
						$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('endpoint'=>$Data['endpoint'],'pubkey'=>$Data['pubkey'],'myid'=>intval($Data['myid'])+rand(100,99999),'offset'=>rand(100,9999),'time'=>time()),1);
						$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
					}
					else
					{
						return false;
					}
				}
				$MyID = $resx[0]['myid'];
				$MyOffset = $resx[0]['offset'];
				$PeerTable = array();
				$resu = $SQL->SelectDBsecure('*','AuthTable','1','=','1',array(),999999);
				if(is_array($resu))
				foreach($resu as $session)
				{
					if($session['session'] != $Deviceid and !empty($session['endpoint']))
					{
						$PeerTable[$session['label']] = array('endpoint'=>$session['endpoint'],'pubkey'=>$session['pubkey'],'myid'=>intval($MyID+$session['offset']),'peerid'=>intval($session['myid']+$MyOffset));
					}
				}
				return $PeerTable;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
}

trait ExchangeController
{
	public function Exchanger($SQL,$Ssalt,$Data,$Deviceid)
	{
		if(!isset($SQL,$Deviceid,$Data,$Ssalt) or empty($Ssalt) or empty($Data) or empty($SQL) or empty($Deviceid))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$Ssalt = $SQL->SecureDBQuery($Ssalt,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(isset($resx[0]['cantoken']) and !empty($resx[0]['cantoken']))
				{
					if(isset($Data['TokenValidate']) and !empty($Data['TokenValidate']))
					{
						if($Data['TokenValidate'] == sha1($resx[0]['cantoken'].$Ssalt))
						{
							$Identifier = $this->ComputeHash($Deviceid,$resx[0]['cantoken']);
							$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('cantoken'=>NULL,'token'=>$resx[0]['cantoken'],'identifier'=>$Identifier,'time'=>time()),1);
							return true;
						}
						else
						{
							return false;
						}
					}
					else
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	
	private function ComputeHash($text,$salt)
	{
		if(strlen($salt) % 2 == 0)
			return str_rot13(base64_encode(hash("sha256",base64_encode($text).md5($salt))));
		else
			return str_rot13(base64_encode(hash("sha256",hash('sha1',$salt).base64_encode($text))));
	}
}

trait SignalController
{
	public function ExtractSignal($SQL,$Identifier)
	{
		if(!isset($SQL,$Identifier) or empty($SQL) or empty($Identifier))
			return false;
		if($SQL->InitDB())
		{
			$Identifier = $SQL->SecureDBQuery($Identifier,true);
			$resx = $SQL->SelectDBsecure('*','AuthTable','identifier','=','?',array($Identifier));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				return array('Deviceid'=>$resx[0]['session'], 'Token'=>$resx[0]['token'], 'IVR'=>$resx[0]['ivr']);
			}
			else
			{
				return null;
			}
		}
		else
		{
			return null;
		}
	}
}

trait AuthController
{
	public function InfoHandler($SQL,$Handler)
	{
		if(!isset($SQL,$Handler) or empty($SQL) or empty($Handler))
			return null;
		try{
			if($SQL->InitDB())
			{
				$resx = $SQL->SelectDBsecure('*','AuthTable','handler','=','?',array($Handler));
				if(isset($resx[0]) and !empty($resx[0]))
				{
					$SQL->CloseDB();
					return array('IVR'=>$resx[0]['ivr'],'HPriv'=>$resx[0]['hpriv'],'Session'=>$resx[0]['session']);
				}
				else
				{
					$SQL->CloseDB();
					return null;
				}
			}
			else
			{
				return null;
			}
		}
		catch(Exception $e)
		{
			return null;
		}
	}
	
	public function PreAuth($SQL,$Crypto,$Deviceid)
	{
		if(!isset($SQL,$Deviceid,$Crypto) or empty($SQL) or empty($Deviceid) or empty($Crypto))
			return null;
		try{
			if($SQL->InitDB())
			{
				$Handler = $this->GenerateString(rand(22,26));
				$IVR = $this->GenerateString(16);
				$HKey = $Crypto->GenKeyPair(2048);
				if(!isset($HKey) or empty($HKey))
					return null;
				$resx = $SQL->SelectDBsecure('*','AuthTable','session','=','?',array($Deviceid));
				if(isset($resx[0]) and !empty($resx[0]))
				{
					$SQL->UpdateDBsecure('AuthTable','session','=','?',array($Deviceid),array('session'=>$Deviceid,'handler'=>$Handler,'ivr'=>$IVR,'hpub'=>$HKey['PUBKEY'],'hpriv'=>$HKey['PRVKEY'],'time'=>time()),1);
					$SQL->CloseDB();
				}
				else
				{
					$SQL->InsertDBsecure('AuthTable',array('session'=>$Deviceid,'handler'=>$Handler,'ivr'=>$IVR,'hpub'=>$HKey['PUBKEY'],'hpriv'=>$HKey['PRVKEY'],'time'=>time()));
					$SQL->CloseDB();
				}
				
				return array('Handler'=>$Handler,'IVR'=>$IVR,'HPub'=>$HKey['PUBKEY'],'HPriv'=>$HKey['PRVKEY']);
			}
			else
			{
				return null;
			}
		}
		catch(Exception $e)
		{
			return null;
		}
	}
	
	public function GenerateNormalString($length = 20)
	{
		$chars =  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.
				'0123456789';
		$str = '';
		$max = strlen($chars) - 1;
		for ($i=0; $i < $length; $i++)
			$str .= $chars[mt_rand(0, $max)];
		return $str;
	}
	
	public function GenerateString($length = 20)
	{
		$chars =  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.
				'0123456789`-=~!@#$%^&*()_+,./<>?;:[]{}|';
		$str = '';
		$max = strlen($chars) - 1;
		for ($i=0; $i < $length; $i++)
			$str .= $chars[mt_rand(0, $max)];
		return $str;
	}
}
?>
