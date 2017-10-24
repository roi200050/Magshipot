<?php
	try
	{
		$ip = "null";
		if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		    $ip = $_SERVER['HTTP_CLIENT_IP'];
		} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
		    $ip = $_SERVER['REMOTE_ADDR'];
		}
		/*
		$mac = shell_exec('arp -a ' . escapeshellarg($ip));

		// can be that the IP doesn't exist or the host isn't up (spoofed?)
		// check if we found an address
		if(empty($mac)) {
		    die("No mac address for $ip not found");
		}
		$pattern = '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})';
		preg_match($pattern, $mac, $matches);
		echo $matches[0];
		// having it
		echo "mac address for $ip: $mac";
		*/
		header ('Location: http://192.168.14.174/done.html ');//change IP!!!!
		$fname = './logs/'.microtime().".txt";
		$handle = fopen($fname, "a");
		fwrite($handle, $ip);
		fwrite($handle, "|");
		fwrite($handle, $_GET['info']);
		fclose($handle);
		exit;
	} 
	catch (Exception $e) 
	{
	    echo 'Caught exception: ',  $e->getMessage(), "\n";
	}
?>