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

//set our base response with an 'error' of false
$result = array('error'=>false);

//get action from the URL
if(isset($_GET['action'])){
	$action = $_GET['action'];
}else {
	exit();//we have nothing to do here so kill it
}


//login
if($action === "login") {
	if(!isset($_POST['username'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing Username.";
		echo json_encode($result); 
        return;
	}else{
		$username = $_POST['username'];
	}
	if(!isset($_POST['password'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing Password.";
		echo json_encode($result); 
        return;
	}else{
		$password = $_POST['password'];
	}

	if(!preg_match("/^(?=[a-zA-Z0-9._]{4,25}$)(?!.*[_.]{2})[^_.].*[^_.]$/", $username)){
        //if there is a non-approved character 
        $result['error']=true;
        $result['message'] = "
		Password requirements
		Only contains alphanumeric characters, underscore and dot.
		Underscore and dot can't be at the end or start of a username (e.g _username / username_ / .username / username.).
		Underscore and dot can't be next to each other (e.g user_.name).
		Underscore or dot can't be used multiple times in a row (e.g user__name / user..name).
		Number of characters must be between 4 to 25.";
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }
	
	$sql = $conn->query("SELECT * FROM users WHERE username='$username'");
    if($sql->num_rows == 1){
		$row = $sql->fetch_assoc();
		//create easy to use vars for following user checks
		$id = $row['id'];
		$username = $row['username'];
		$email = $row['email'];
		$passwordhash = $row['password'];
		$active = $row['active'];

		//verify password provided matches the db hash
		$pwmatch = password_verify($password, $passwordhash);
		if(!$pwmatch){
			//if our passwords do not match db, error out and let them know. 
			$result['error'] = true;
			$result['message'] = "Incorrect Password.";
			echo json_encode($result); 
			return;
		}
		// at this point we are good to create the token, and send the info back to the user
		$IAT = time(); //get current time for issued at
		$NBF = 1357000000; //9 years ago - this is "Not BeFore", not sure if its required... guess could make it so you have to wait to login.. but idk why
		$EXP = $IAT + $JWT_EXPIRES_IN; // add the expires in amount from config in seconds
		$token = array(
			"iss" => $JWT_ISS,
			"aud" => $JWT_AUD,
			"iat" => $IAT,
			"nbf" => $NBF,
			"exp" => $EXP,
			"data" => array(
				"id" => $id,
				"username" => $username
			)
		);
		
		$jwt = JWT::encode($token, $JWT_KEY);
		
		$result['message'] = "successfully logged in";
		$result['token'] = $jwt;

	}else{
        //no user found
		$result['error'] = true;
		$result['message'] = "NO USER FOUND.";
		echo json_encode($result); 
        return;
    }

}











// try {
// 	$decoded = JWT::decode($jwt, $JWT_KEY, array('HS256'));
// 	echo "<pre>";
// 	print_r($decoded);
// } catch(Exception $e) {
// 	echo "<br>invalid token";
// }



//If we have made it this far, send the result back to the requester
echo "<pre>";
echo json_encode($result,JSON_PRETTY_PRINT);
echo "</pre>";

// echo json_encode($result); 
?>
