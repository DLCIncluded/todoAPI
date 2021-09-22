<?PHP
// Main entry point for requests for API
require("./config/config.php");
require("./config/dbconn.php");
//this gets us $conn to use for sql

//Include JWT for PHP
require_once 'jwt/src/BeforeValidException.php';
require_once 'jwt/src/ExpiredException.php';
require_once 'jwt/src/SignatureInvalidException.php';
require_once 'jwt/src/JWT.php';
use \Firebase\JWT\JWT;
define('ALGORITHM', 'HS256');
$alg = 'H256';


$IAT = time(); //get current time for issued at
$NBF = 1357000000; //9 years ago - this is Not BeFore, not sure if its required... guess could make it so you have to wait to login.. but idk why
$EXP = $IAT + $JWT_EXPIRES_IN; // add the expires in amount from config in seconds

$token = array(
	"iss" => $JWT_ISS,
	"aud" => $JWT_AUD,
	"iat" => $IAT,
	"nbf" => $NBF,
	"exp" => $EXP,
	"data" => array(
		"id" => 1,
		"username" => "dlcincluded"
	)
);

$jwt = JWT::encode($token, $JWT_KEY);

echo $jwt;

try {
	$decoded = JWT::decode($jwt, $JWT_KEY, array('HS256'));
	echo "<pre>";
	print_r($decoded);
} catch(Exception $e) {
	echo "<br>invalid token";
}







//post requests



?>
