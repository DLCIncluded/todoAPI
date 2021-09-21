<?PHP
	require("dbconfig.php");
	$conn = new mysqli('localhost', $DB_USERNAME, $DB_PASSWORD, $DB_DATABASE, NULL);
	if($conn->connect_error){
		die('Connection Error ('. $conn->connect_errno . ') ' . $conn->connect_error);
	}//if we get no error, we have a successfull connection
?>