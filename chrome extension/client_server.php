<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Origin: null");
header("Content-Type: application/json");


$data = json_decode(file_get_contents("php://input"));
//echo gettype($data->URL);
//$string = $data->URL.",".$data->IPAddress.",".$data->URL_Length.",".$data->Tiny_URL.",".$data->AtSymbol.",".$data->Redirecting.",".$data->PrefixSuffix_in_domain.",".$data->No_of_Sub_Domains.",".$data->HTTPS.",".$data->Favicon.",".$data->Port.",".$data->HTTPSinURLsdomainpart.",".$data->RequestURL.",".$data->Anchor.",".$data->ScriptLink.",".$data->SFH.",".$data->mailto.",".$data->iFrames;
$string = $data->URL.",".$data->IPAddress.",".$data->URL_Length.",".$data->Tiny_URL.",".$data->AtSymbol.",".$data->Redirecting.",".$data->PrefixSuffix_in_domain.",".$data->No_of_Sub_Domains.",".$data->HTTPS.",".$data->RequestURL.",".$data->Anchor.",".$data->ScriptLink.",".$data->SFH.",".$data->mailto.",".$data->iFrames;

$result = shell_exec('python check.py ' . escapeshellarg(json_encode($string)));
echo $result;


//$command = escapeshellcmd('C:/xampp/htdocs/C_E/python_code.py');
//$output = shell_exec($command);
//echo $output;*/



//echo gettype($output);

// Replace the path with the path of your python2.x installation.
//$decision=exec("C:/Users/Lenovo/AppData/Roaming\Microsoft\Windows\Start Menu\Programs\Python 3.7 test.py $site 2>&1 ");
//echo $decision;
?>

