$(document).ready(function () {
    $("#postComment").on("click", function () {
        var commentInput = $("#commentInput").val();
        $.ajax({
            type: 'POST',
            url: 'CrossSiteScriptingStored/stored-xss',
            data: JSON.stringify({text: commentInput}),
            contentType: "application/json",
            dataType: 'json'
        }).then(
            function () {
                getChallenges();
                $("#commentInput").val('');
            }
        )
    })

    getChallenges();

    // Comments are built with DOM APIs and .text(), so the stored value is set as character data
    // and is never parsed as markup. Splicing it into an HTML string and calling .append() made
    // this the sink: whatever a previous visitor stored ran in every later viewer's browser.
    // Encoding belongs here, at the point of output, in the context the value is used - not on
    // the way into the store, which leaves the sink one refactor away from being live again.
    function renderComment(comment) {
        var avatar = $('<div class="pull-left">').append(
            $('<img class="avatar" src="images/avatar1.png" alt="avatar"/>'));

        var heading = $('<div class="comment-heading">')
            .append($('<h4 class="user">').text(comment.user))
            .append($('<h5 class="time">').text(comment.dateTime));

        var body = $('<div class="comment-body">')
            .append(heading)
            .append($('<p>').text(comment.text));

        return $('<li class="comment">').append(avatar).append(body);
    }

    function getChallenges() {
        $("#list").empty();
        $.get('CrossSiteScriptingStored/stored-xss', function (result, status) {
            for (var i = 0; i < result.length; i++) {
                $("#list").append(renderComment(result[i]));
            }

        });
    }
})
