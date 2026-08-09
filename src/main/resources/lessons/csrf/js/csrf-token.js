// Fetches the anti-CSRF token of the current session and adds it to the forms of this lesson.
// Only same origin script can read it, which is exactly what makes it a CSRF defence.
webgoat.customjs.csrfToken = '';

webgoat.customjs.addCsrfToken = function () {
    var headers_to_set = {};
    headers_to_set['X-CSRF-TOKEN'] = webgoat.customjs.csrfToken;
    return headers_to_set;
}

$(document).ready(function () {
    $.get('csrf/token', function (result) {
        webgoat.customjs.csrfToken = result.token;
        $('input[name="validateReq"]').val(result.token);
    });
})
