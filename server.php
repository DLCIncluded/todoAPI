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
	return;
}


//user controls
if($action === "login") {
	if(!isset($_POST['username'])){
		// http_response_code(401);
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
        $result['message'] = "Invalid username";
		// Password requirements
		// Only contains alphanumeric characters, underscore and dot.
		// Underscore and dot can't be at the end or start of a username (e.g _username / username_ / .username / username.).
		// Underscore and dot can't be next to each other (e.g user_.name).
		// Underscore or dot can't be used multiple times in a row (e.g user__name / user..name).
		// Number of characters must be between 4 to 25.
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

		$result['id'] = $id;
		$result['username'] = $username;
		$result['email'] = $email;

	}else{
        //no user found
		$result['error'] = true;
		$result['message'] = "NO USER FOUND.";
		echo json_encode($result); 
        return;
    }

}

if($action === "register") {
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
		//no password given 
		$result['error'] = true;
		$result['message'] = "Missing Password.";
		echo json_encode($result); 
        return;
	}else{
		$password = $_POST['password'];
	}
	if(!isset($_POST['email'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing email.";
		echo json_encode($result); 
		return;
	}else{
		$email = $_POST['email'];
	}

	if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
        //if email is invalid

        $result['error']=true;
        $result['message'] = "Invalid Email.";
        echo json_encode($result);
        return;   
    }

	if(!preg_match("/^(?=[a-zA-Z0-9._]{4,25}$)(?!.*[_.]{2})[^_.].*[^_.]$/", $username)){
        //if there is a non-approved character 
        $result['error']=true;
        $result['message'] = "Invalid username";
		// Password requirements
		// Only contains alphanumeric characters, underscore and dot.
		// Underscore and dot can't be at the end or start of a username (e.g _username / username_ / .username / username.).
		// Underscore and dot can't be next to each other (e.g user_.name).
		// Underscore or dot can't be used multiple times in a row (e.g user__name / user..name).
		// Number of characters must be between 4 to 25.
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }

	if(!password_strength_check($password)){
		$result['error']=true;
        $result['message'] = "Password does not meet requirements.";
        echo json_encode($result);
        return; 
	}

	//check if username taken
    $sql = $conn->query("SELECT * FROM users WHERE username='$username'");
    if($sql->num_rows >= 1){
        //if we have a user, error out
        $result['error']=true;
        $result['message'] = "The username $username is already in use.";
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }

    //check if email taken
    $sql = $conn->query("SELECT * FROM users WHERE email='$email'");
    if($sql->num_rows >= 1){
        //if we have a user, error out
        $result['error']=true;
        $result['message'] = "The email $email is already in use.";
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }

	$password = password_hash($password, PASSWORD_BCRYPT); //create password hash

    //at this point user is valid to input into db
    
    $sql = $conn->query("INSERT INTO users (username,email,password) 
        VALUES 
        ('$username','$email','$password');
    ");

	if($sql){
		$result['message'] = "Account Successfully Registered.";
	}
	else {
		$result['error'] = true;
		$result['message'] = "There was an error saving to the DB";
	}

}

if($action === "verifytoken") {
	if(!isset($_POST['token'])){
		// http_response_code(401);
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}

	if(validate_token($token)){
		$result['message'] = "Token Valid.";
	}else{
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}
	// try {
	// 	$decoded = JWT::decode($token, $JWT_KEY, array('HS256'));
	// 	$result['message'] = "Token Valid.";
	// } catch(Exception $e) {
	// 	$result['error'] = true;
	// 	$result['message'] = "Token Invalid.";
	// 	echo json_encode($result); 
    //     return;
	// }
}

if($action === "usernamecheck") {
	if(!isset($_POST['username'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing Username.";
		echo json_encode($result); 
        return;
	}else{
		$username = $_POST['username'];
	}
	//check if username taken
	$sql = $conn->query("SELECT * FROM users WHERE username='$username'");
	if($sql->num_rows >= 1){
		//if we have a user, error out
		$result['error']=true;
		$result['message'] = "The username '$username' is already in use.";
		echo json_encode($result); 
		return;
	}else{
		$result['message'] = "The username '$username' is available.";
	}
}

if($action === "emailcheck") {
	if(!isset($_POST['email'])){
		//no email given 
		$result['error'] = true;
		$result['message'] = "Missing Email.";
		echo json_encode($result); 
        return;
	}else{
		$email = $_POST['email'];
	}
	//check if email taken
	$sql = $conn->query("SELECT * FROM users WHERE email='$email'");
	if($sql->num_rows >= 1){
		//if we have a user, error out
		$result['error']=true;
		$result['message'] = "The email '$email' is already in use.";
		echo json_encode($result); 
		return;
	}else{
		$result['message'] = "The email '$email' is available.";
	}
}

if($action === "newlist"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['token'])){
		// http_response_code(401);
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}

	if(!validate_token($token)){
		//if token invalid for whatever reason, stop now
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM users WHERE id=$userid");

	if($sql->num_rows != 1){
		//we cannot find a user with that id
		$result['error'] = true;
		$result['message'] = "Invalid User id provided.";
		echo json_encode($result); 
        return;
	}

	// now that we know the user exists lets start verify that the user sent all the required data

	if(!isset($_POST['list_name'])){
		//no list_name given 
		$result['error'] = true;
		$result['message'] = "Missing List Name.";
		echo json_encode($result); 
        return;
	}else{
		$list_name = $_POST['list_name'];
	}

	if(!isset($_POST['list_description'])){
		//no list_description given 
		$result['error'] = true;
		$result['message'] = "Missing List Description.";
		echo json_encode($result); 
        return;
	}else{
		$list_description = $_POST['list_description'];
	}

	//at this point we have what we need, lets create the list and give the user access to it

	$sql = $conn->query("SELECT id FROM lists WHERE name='$list_name' AND owner=$userid");
	if($sql->num_rows > 0){
		$result['error'] = true;
		$result['message'] = "You cannot have more than one list with the same name";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("INSERT INTO lists (name,description,owner) 
        VALUES 
        ('$list_name','$list_description','$userid');
    ");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an error saving the list";
		echo json_encode($result); 
        return;
	}

	//now we have to get that list, and give the user access (its weird i know...)
	$sql = $conn->query("SELECT id FROM lists WHERE name='$list_name' AND owner=$userid");
	if($sql->num_rows == 1){
		$row = $sql->fetch_assoc();
		$listid = $row['id'];
	}
	

	$sql = $conn->query("INSERT INTO user_lists (user_id,list_id,sort_order) 
        VALUES 
        ('$userid','$listid',0);
    ");

	if(!$sql){
		$result['error'] = true;
		// $result['message'] = "There was an error adding the list to the user";
		$result['message'] = $conn->error;
		echo json_encode($result); 
		return;
	}

	// at this point list should be created, and user should have access to it
	$result['message'] = "Successfully created list: $list_name";

}

if($action === "newitem"){

	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['token'])){
		// http_response_code(401);
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}

	if(!validate_token($token)){
		//if token invalid for whatever reason, stop now
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM users WHERE id=$userid");

	if($sql->num_rows != 1){
		//we cannot find a user with that id
		$result['error'] = true;
		$result['message'] = "Invalid User id provided.";
		echo json_encode($result); 
        return;
	}

	// now that we know the user exists lets start verify that the user sent all the required data

	if(!isset($_POST['item_name'])){
		//no item_name given 
		$result['error'] = true;
		$result['message'] = "Missing Item Name.";
		echo json_encode($result); 
        return;
	}else{
		$item_name = $_POST['item_name'];
	}

	if(!isset($_POST['item_type'])){
		//no item_type given 
		//this shouldnt happen but still
		$result['error'] = true;
		$result['message'] = "Missing List type."; 
		echo json_encode($result); 
        return;
	}else{
		$item_type = $_POST['item_type'];
	}

	if(!isset($_POST['item_list_id'])){
		//no item_list_id given 
		$result['error'] = true;
		$result['message'] = "Missing List id.";
		echo json_encode($result); 
        return;
	}else{
		$item_list_id = $_POST['item_list_id'];
	}

	//at this point we have what we need, lets verify the list exists, and the user has access to it
	$sql = $conn->query("SELECT * FROM lists WHERE id='$item_list_id'");
	if($sql->num_rows < 1){
		$result['error'] = true;
		$result['message'] = "That list does not exist";
		echo json_encode($result); 
        return;
	}else{
		$row = $sql->fetch_assoc();
		$listowner = $row['owner']; // not sure we need this right now but we have it in case
	}

	$sql = $conn->query("SELECT * FROM user_lists WHERE list_id=$item_list_id AND user_id=$userid");
	if($sql->num_rows < 1){
		$result['error'] = true;
		$result['message'] = "You do not have permission for this list";
		echo json_encode($result); 
        return;
	}
	
	//at this point the user should have access to the list, and we can proceed to add the list item
	$updated = time();
	$sql = $conn->query("INSERT INTO todos (name,listid,updated,sort_order,type) 
        VALUES 
        ('$item_name','$item_list_id',$updated,0,'$item_type');
    ");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an error saving the list item";
		echo json_encode($result); 
        return;
	}

	// at this point list should be created, and user should have access to it
	$result['message'] = "Successfully created list item: '$item_name'";

}

function validate_token($token){
	global $JWT_KEY;
	try {
		$decoded = JWT::decode($token, $JWT_KEY, array('HS256'));
		return true;
	} catch(Exception $e) {
        return false;
	}
}

function password_strength_check($password, $min_len = 8, $max_len = 255, $req_digit = 1, $req_lower = 1, $req_upper = 1, $req_symbol = 1) {
    // Build regex string depending on requirements for the password
    $regex = '/^';
    if ($req_digit == 1) { $regex .= '(?=.*\d)'; }              // Match at least 1 digit
    if ($req_lower == 1) { $regex .= '(?=.*[a-z])'; }           // Match at least 1 lowercase letter
    if ($req_upper == 1) { $regex .= '(?=.*[A-Z])'; }           // Match at least 1 uppercase letter
    if ($req_symbol == 1) { $regex .= '(?=.*[^a-zA-Z\d])'; }    // Match at least 1 character that is none of the above
    $regex .= '.{' . $min_len . ',' . $max_len . '}$/';

    if(preg_match($regex, $password)) {
        return TRUE;//pw is valid
    } else {
        return FALSE; //pw is not valid
    }
}


//If we have made it this far, send the result back to the requester
//this is to make it easier to read for myself, but need to go back to just json encode for prod
// echo "<pre>";
// echo json_encode($result,JSON_PRETTY_PRINT);
// echo "</pre>";

echo json_encode($result); 
?>
