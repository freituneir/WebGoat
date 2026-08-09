function submit_secret_credentials() {
    // A credential must never be embedded in code that is shipped to the browser, and it must
    // never be sent in a payload that a proxy can read back. Obfuscating the strings changed
    // nothing: anything the page can decode, so can anyone watching the request. The demo request
    // below therefore carries no credential at all -- the server authenticates the session that is
    // already established instead.
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
    xhttp['setRequestHeader']('Content-Type', 'application/json');
    xhttp['send'](JSON.stringify({}));
}
