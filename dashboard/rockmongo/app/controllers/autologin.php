<?php

import("classes.BaseController");

class AutologinController extends BaseController {

	public function onBefore() {
		global $MONGO;
		parse_str($_SERVER["QUERY_STRING"]);
		echo "connect to .....user=".$user." & pass=".$pass." & instance= ".$instance;

		//authenticate
		$server = MServer::serverWithIndex(0);
		if (!$server->auth($user, $pass, $instance)) {
			$this->message = rock_lang("can_not_auth");
				$this->display();
				return;
			}
		
		//remember user
		import("models.MUser");
		MUser::login($user, $pass, 0, $instance, 3600);
			
		$this->redirect("admin.index", array( "host" => 0 ));

	}	
}

?>