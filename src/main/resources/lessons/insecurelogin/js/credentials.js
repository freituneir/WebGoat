function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
	//the credentials live on the server; nothing is shipped to the page and nothing is put
	//on the wire, so a packet capture has nothing to show
	xhttp['send']()
}
