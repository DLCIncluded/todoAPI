<?PHP
// Main entry point for requests for API
requrire("config.php")
require("./config/dbconn.php");
//this gets us $conn to use for sql

//Include JWT for PHP
require_once 'jwt/src/BeforeValidException.php';
require_once 'jwt/src/ExpiredException.php';
require_once 'jwt/src/SignatureInvalidException.php';
require_once 'jwt/src/JWT.php';
use \Firebase\JWT\JWT;



//post requests



?>
