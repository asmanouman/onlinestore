<?php
 
/**
 * @author PIE REGISTER
 * @link pieregister.com
 */
if ( ! defined( 'ABSPATH' ) ) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;   
}

/*
    * Get Pie Register Dir Name
*/

$piereg_dir_path = dirname(__FILE__);
//define('PIEREG_DIR_NAME',$piereg_dir_path);

/*
    * Include PR Files
*/

class Firebase {
 
    // sending push message to single user by firebase reg id
    public function send($to, $message) {
        $fields = array(
            'to' => $to,
            'data' => $message,
        );
        return $this->sendPushNotification($fields);
    }
 
    // function makes curl request to firebase servers
    private function sendPushNotification($fields) {
         
        require_once(PIEREG_DIR_NAME.'/classes/app/config.php');
 
        // Set POST variables
        $url = 'https://fcm.googleapis.com/fcm/send';
 
        $headers = array(
            'Authorization: key=' . FIREBASE_API_KEY,
            'Content-Type: application/json'
        );
        // Open connection
        $ch = curl_init();
 
        // Set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $url);
 
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
 
        // Disabling SSL Certificate support temporarly
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
 
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($fields));
 
        // Execute post
        $result = curl_exec($ch);
        if ($result === FALSE) {
            die('Curl failed: ' . curl_error($ch));
        }
 
        // Close connection
        curl_close($ch);
 
        return $result;
    }
}
?>