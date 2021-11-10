<?PHP
date_default_timezone_set('America/Detroit');
// $updated = date('Y-m-d');
// echo $updated;

$date1 = "2021-11-08 0:33:48";
$datetimestamp1 = strtotime($date1);
$newformat = date('Y-m-d',$datetimestamp1);
$datetimestamp1 = strtotime($newformat);
echo $newformat;
echo "<br>";
$date = date('Y-m-d');
echo $date;
echo "<br>";
$currentDateTime = strtotime($date);

if($datetimestamp1 < $currentDateTime){
	echo "Not today";
}else{
	echo "Today";
}



?>