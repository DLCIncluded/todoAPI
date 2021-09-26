<?PHP
header('Access-Control-Allow-Origin: *');
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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
		$list_id = $row['id'];
	}
	

	$sql = $conn->query("INSERT INTO user_lists (user_id,list_id,sort_order) 
        VALUES 
        ('$userid','$list_id',0);
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

if($action === "getlists"){
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM user_lists WHERE user_id=$userid ORDER BY sort_order ASC");

	if($sql->num_rows > 0){
		$lists = array();
		while($row = $sql->fetch_assoc()){
			$list_id = $row['list_id'];
			$sort_order = $row['sort_order'];
			$getlists = $conn->query("SELECT * FROM lists WHERE id=$list_id");
			if($getlists->num_rows == 0){
				$result['error'] = true;
				$result['message'] = "There was an error pulling lists, please reach out to site admin.";
				echo json_encode($result); 
				return;
			}
			$listinfo = $getlists->fetch_assoc();
			$list_id = $listinfo['id'];
			$list_name = $listinfo['name'];
			$list_description = $listinfo['description'];
			$list_owner = $listinfo['owner'];

			$getowner = $conn->query("SELECT username FROM users WHERE id=$list_owner");
			$ownerinfo = $getowner->fetch_assoc();
			$ownername = $ownerinfo['username'];

			$list = array(
				'id' => $list_id,
				'name' => $list_name,
				'description' => $list_description,
				'owner' => $ownername,
				'sort_order' => $sort_order
			);
			array_push($lists,$list);
		}
		$result['message'] = "Successfully pulled lists.";
		$result['lists'] = $lists;
	}else{
		$result['message'] = "No friends lists.";
	}
}

if($action === "deletelist"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['list_id'])){
		//no list_id given 
		$result['error'] = true;
		$result['message'] = "Missing List id.";
		echo json_encode($result); 
        return;
	}else{
		$list_id = $_POST['list_id'];
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM lists WHERE id=$list_id AND owner=$userid");
	if($sql->num_rows <= 0){
		//we cannot find list with that ID, that this user owns
		$result['error'] = true;
		$result['message'] = "Either we could not find that list, or you do not own the list.";
		echo json_encode($result); 
        return;
	}
	$sql = $conn->query("SELECT * FROM user_lists WHERE list_id=$list_id AND user_id=$userid");
	if($sql->num_rows <= 0){
		//that user does not have access to that list at all
		$result['error'] = true;
		$result['message'] = "You do not have access to this list.";
		echo json_encode($result); 
        return;
	}
	
	$sql = $conn->query("DELETE FROM lists WHERE id=$list_id"); // delete the list
	$sql2 = $conn->query("DELETE FROM user_lists WHERE list_id=$list_id"); //delete the permissions for the list for all users
	$sql3 = $conn->query("DELETE FROM todos WHERE list_id=$list_id"); // delete all todos linked to this list
	if($sql && $sql2 && $sql3){
		$result['message'] = "Successfully deleted list.";
	}else{
		$result['error'] = true;
		$result['message'] = "Something went wrong deleting list_id ($list_id), please reach out to the site admin.";
	}
	
}

if($action === "newtodo"){

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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	if(!isset($_POST['todo_name'])){
		//no todo_name given 
		$result['error'] = true;
		$result['message'] = "Missing Item Name.";
		echo json_encode($result); 
        return;
	}else{
		$todo_name = $_POST['todo_name'];
	}

	if(!isset($_POST['todo_type'])){
		//no todo_type given 
		//this shouldnt happen but still
		$result['error'] = true;
		$result['message'] = "Missing List type."; 
		echo json_encode($result); 
        return;
	}else{
		$todo_type = $_POST['todo_type'];
	}

	if(!isset($_POST['list_id'])){
		//no list_id given 
		$result['error'] = true;
		$result['message'] = "Missing List id.";
		echo json_encode($result); 
        return;
	}else{
		$list_id = $_POST['list_id'];
	}

	//at this point we have what we need, lets verify the list exists, and the user has access to it
	$sql = $conn->query("SELECT * FROM lists WHERE id='$list_id'");
	if($sql->num_rows < 1){
		$result['error'] = true;
		$result['message'] = "That list does not exist";
		echo json_encode($result); 
        return;
	}else{
		$row = $sql->fetch_assoc();
		$listowner = $row['owner']; // not sure we need this right now but we have it in case
	}

	$sql = $conn->query("SELECT * FROM user_lists WHERE list_id=$list_id AND user_id=$userid");
	if($sql->num_rows < 1){
		$result['error'] = true;
		$result['message'] = "You do not have permission for this list";
		echo json_encode($result); 
        return;
	}
	
	//at this point the user should have access to the list, and we can proceed to add the list item
	$updated = time();
	$sql = $conn->query("INSERT INTO todos (name,list_id,updated,sort_order,type) 
        VALUES 
        ('$todo_name','$list_id',$updated,0,'$todo_type');
    ");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an error saving the todo item";
		echo json_encode($result); 
        return;
	}

	// at this point list should be created, and user should have access to it
	$result['message'] = "Successfully created list item: '$todo_name'";

}

if($action === "gettodos"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['list_id'])){
		//no list_id given 
		$result['error'] = true;
		$result['message'] = "Missing list_id.";
		echo json_encode($result); 
        return;
	}else{
		$list_id = $_POST['list_id'];
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
	}else{
		$user = extract_user_token($token);
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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


	$sql = $conn->query("SELECT * FROM user_lists WHERE user_id=$userid AND list_id=$list_id");
	if($sql->num_rows < 1){
		//if user does not have access to this list, then stop
		$result['error'] = true;
		$result['message'] = "You do not have access to that list.";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM todos WHERE list_id=$list_id ORDER BY sort_order ASC");

	if($sql->num_rows > 0){

		$getlist = $conn->query("SELECT * FROM lists WHERE id=$list_id");
		if($getlist->num_rows == 0){
			$result['error'] = true;
			$result['message'] = "There was an error pulling list info, please reach out to site admin.";
			echo json_encode($result); 
			return;
		}

		$list_info = $getlist->fetch_assoc();

		$list_id = $list_info['id'];
		$list_name = $list_info['name'];
		$list_description = $list_info['description'];
		$list_owner = $list_info['owner'];
		$getowner = $conn->query("SELECT username FROM users WHERE id=$list_owner");
		$ownerinfo = $getowner->fetch_assoc();
		$ownername = $ownerinfo['username'];

		$todos = array();
		while($row = $sql->fetch_assoc()){
			$todo_id = $row['id'];
			$todo_name = $row['name'];
			$todo_done = $row['done'];
			$todo_updated = $row['updated'];
			$todo_sort_order = $row['sort_order'];
			$todo_type = $row['type'];

			$todo = array(
				'id' => $todo_id,
				'name' => $todo_name,
				'done' => $todo_done,
				'updated' => $todo_updated,
				'sort_order' => $todo_sort_order,
				'type' => $todo_type
			);
			array_push($todos,$todo);
		}
		
		$result['message'] = "Successfully pulled todos.";
		$result['list'] = array(
			'list_id' => $list_id,
			'list_name' => $list_name,
			'list_description' => $list_description,
			'list_ownerid' => $list_owner,
			'list_owneruser' => $ownername
		);
		$result['todos'] = $todos;
	}else{
		$result['message'] = "No todo items.";
	}
}

if($action === "deletetodo"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['todo_id'])){
		//no todo_id given 
		$result['error'] = true;
		$result['message'] = "Missing todo id.";
		echo json_encode($result); 
        return;
	}else{
		$todo_id = $_POST['todo_id'];
	}

	if(!isset($_POST['token'])){
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}

	if(!validate_token($token)){
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}else{
		$user = extract_user_token($token);
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM todos WHERE id=$todo_id");
	if($sql->num_rows <= 0){
		//we cannot find list with that ID
		$result['error'] = true;
		$result['message'] = "Could not find that todo.";
		echo json_encode($result); 
        return;
	}
	$row = $sql->fetch_assoc();
	$list_id = $row['list_id'];


	$sql = $conn->query("SELECT * FROM user_lists WHERE list_id=$list_id AND user_id=$userid");
	if($sql->num_rows <= 0){
		//that user does not have access to that list at all
		$result['error'] = true;
		$result['message'] = "You do not have access to this list.";
		echo json_encode($result); 
        return;
	}
	
	$sql = $conn->query("DELETE FROM todos WHERE id=$todo_id"); // delete the todo
	
	if($sql){
		$result['message'] = "Successfully deleted todo.";
	}else{
		$result['error'] = true;
		$result['message'] = "Something went wrong deleting todo_id ($todo_id), please reach out to the site admin.";
	}
	
}

if($action === "friendrequest"){
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	if(!isset($_POST['friend_id'])){
		//no friend_id given 
		$result['error'] = true;
		$result['message'] = "Missing friend id.";
		echo json_encode($result); 
        return;
	}else{
		$friend_id = $_POST['friend_id'];
	}

	$sql = $conn->query("SELECT * FROM users WHERE id=$friend_id");

	if($sql->num_rows != 1){
		//we cannot find a user with that id
		$result['error'] = true;
		$result['message'] = "Invalid Friend User id provided.";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM friends WHERE (requester=$userid AND requestee=$friend_id) OR (requester=$friend_id AND requestee=$userid)");

	if($sql->num_rows == 1){
		//already friends or requested friends
		$result['error'] = true;
		$result['message'] = "Cannot send another friend request to this person, one already exists.";
		echo json_encode($result); 
        return;
	}

	//at this point we should be okay to "send the friend request"

	$sql = $conn->query("INSERT INTO friends (requester,requestee,accepted) 
		VALUES 
		('$userid','$friend_id',0);
	");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an unknown error sending the friend request";
		echo json_encode($result); 
		return;
	}

	// at this point list should be created, and user should have access to it
	$result['message'] = "Successfully sent friend request!";

}

if($action === "getfriends"){
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

	$sql = $conn->query("SELECT * FROM friends WHERE (requestee=$userid AND accepted=1) OR (requester=$userid AND accepted=1)");

	if($sql->num_rows > 0){
		$friends = array();
		while($row = $sql->fetch_assoc()){
			$requesterid = $row['requester'];
			$getusersinfo = $conn->query("SELECT username FROM users WHERE id=$requesterid");
			if($getusersinfo->num_rows == 0){
				//we cannot find a user with that id
				$result['error'] = true;
				$result['message'] = "Unable to process user friends, please reachout to the admin.";
				echo json_encode($result); 
				return;
			}
			$usersinfo = $getusersinfo->fetch_assoc();
			$username = $usersinfo['username'];

			$friend = array(
				'id' => $row['id'],
				'username' => $username,
			);
			array_push($friends,$friend);
		}
		$result['message'] = "Successfully pulled friends.";
		$result['friends'] = $friends;
	}else{
		$result['message'] = "No friends found.";
	}
}

if($action === "pendingfriendrequests"){
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM friends WHERE requestee=$userid AND accepted=0");

	if($sql->num_rows > 0){
		$requests = array();
		while($row = $sql->fetch_assoc()){
			$requesterid = $row['requester'];
			$getusersinfo = $conn->query("SELECT username FROM users WHERE id=$requesterid");
			if($getusersinfo->num_rows == 0){
				//we cannot find a user with that id
				$result['error'] = true;
				$result['message'] = "Unable to process user requests, please reachout to the admin.";
				echo json_encode($result); 
				return;
			}
			$usersinfo = $getusersinfo->fetch_assoc();
			$username = $usersinfo['username'];

			$request = array(
				'id' => $row['id'],
				'username' => $username,
			);
			array_push($requests,$request);
		}
		$result['message'] = "Successfully pulled requests.";
		$result['requests'] = $requests;
	}else{
		$result['message'] = "No requests found.";
	}


}

if($action === "acceptfriendrequest"){
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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
	if(!isset($_POST['request_id'])){
		//no request_id given 
		$result['error'] = true;
		$result['message'] = "Missing request id.";
		echo json_encode($result); 
		return;
	}else{
		$request_id = $_POST['request_id'];
	}

	$sql = $conn->query("SELECT * FROM friends WHERE id=$request_id AND requestee=$userid AND accepted=0");
	if($sql->num_rows !== 1){
		$result['error'] = true;
		$result['message'] = "Friend request does not exist.";
		echo json_encode($result); 
		return;
	}

	$sql = $conn->query("UPDATE friends SET accepted=1 WHERE id=$request_id");
	if($sql){
		$result['message'] = "Friend request accepted.";
	}else{
		$result['error'] = true;
		$result['message'] = "Something went wrong accepting the request.";
		echo json_encode($result); 
		return;
	}

}

if($action === "updatelistsortorder"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['list_id'])){
		//no list_id given 
		$result['error'] = true;
		$result['message'] = "Missing list_id.";
		echo json_encode($result); 
        return;
	}else{
		$list_id = $_POST['list_id'];
	}

	if(!isset($_POST['sort_order'])){
		//no sort_order given 
		$result['error'] = true;
		$result['message'] = "Missing sort_order.";
		echo json_encode($result); 
        return;
	}else{
		$sort_order = $_POST['sort_order'];
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM user_lists WHERE list_id=$list_id AND user_id=$userid");
	if($sql->num_rows !== 1){
		$result['error'] = true;
		$result['message'] = "List does not exist.";
		echo json_encode($result); 
		return;
	}

	$sql = $conn->query("UPDATE user_lists SET sort_order=$sort_order WHERE list_id=$list_id AND user_id=$userid");
	if($sql){
		$result['message'] = "List updated.";
	}else{
		$result['error'] = true;
		$result['message'] = "Something went wrong updating the list.";
		echo json_encode($result); 
		return;
	}

}

if($action === "updatetodosortorder"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['todo_id'])){
		//no todo_id given 
		$result['error'] = true;
		$result['message'] = "Missing todo_id.";
		echo json_encode($result); 
        return;
	}else{
		$todo_id = $_POST['todo_id'];
	}

	if(!isset($_POST['sort_order'])){
		//no sort_order given 
		$result['error'] = true;
		$result['message'] = "Missing sort_order.";
		echo json_encode($result); 
        return;
	}else{
		$sort_order = $_POST['sort_order'];
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM todos WHERE id=$todo_id");
	if($sql->num_rows !== 1){
		$result['error'] = true;
		$result['message'] = "Todo does not exist.";
		echo json_encode($result); 
		return;
	}

	$sql = $conn->query("UPDATE todos SET sort_order=$sort_order WHERE id=$todo_id");
	if($sql){
		$result['message'] = "Todo updated.";
	}else{
		$result['error'] = true;
		$result['message'] = "Something went wrong updating the todo.";
		echo json_encode($result); 
		return;
	}

}

if($action === "markdone"){
	if(!isset($_POST['id'])){
		//no id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['id'];
	}

	if(!isset($_POST['todo_id'])){
		//no todo_id given 
		$result['error'] = true;
		$result['message'] = "Missing todo_id.";
		echo json_encode($result); 
        return;
	}else{
		$todo_id = $_POST['todo_id'];
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
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
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

	$sql = $conn->query("SELECT * FROM todos WHERE id=$todo_id");
	if($sql->num_rows !== 1){
		$result['error'] = true;
		$result['message'] = "Todo does not exist.";
		echo json_encode($result); 
		return;
	}
	//invert the current value (this way the user can uncheck if it was an accident)
	$sql = $conn->query("UPDATE todos SET done=NOT done WHERE id=$todo_id");
	if($sql){
		$result['message'] = "Todo updated.";
	}else{
		$result['error'] = true;
		$result['message'] = "Something went wrong updating the todo.";
		echo json_encode($result); 
		return;
	}

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

function extract_user_token($token){
	global $JWT_KEY;
	try {
		$decoded = JWT::decode($token, $JWT_KEY, array('HS256'));
		return (array) $decoded;
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
//echo "<pre>";
//echo json_encode($result,JSON_PRETTY_PRINT);
//echo "</pre>";

echo json_encode($result); 
?>
