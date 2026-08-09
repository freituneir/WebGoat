/*
 * Attaches the CSRF token to every state changing call WebWolf makes.
 * The token is written as a readable cookie by the server, jQuery sends it back in the header
 * Spring Security expects. Safe methods are left untouched, they carry no token requirement.
 */
(function () {
    var SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

    function currentToken() {
        var cookie = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
        return cookie ? decodeURIComponent(cookie[1]) : null;
    }

    $(document).ready(function () {
        $.ajaxPrefilter(function (options, originalOptions, xhr) {
            var method = (options.type || options.method || 'GET').toUpperCase();
            if (options.crossDomain || SAFE_METHODS.indexOf(method) !== -1) {
                return;
            }
            var token = currentToken();
            if (token) {
                xhr.setRequestHeader('X-XSRF-TOKEN', token);
            }
        });
    });
})();
