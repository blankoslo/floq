function onSuccess(googleUser) {
    // POST session to backend, which does the redirect.
    var form = document.createElement('form');
    form.setAttribute('method', 'POST');
    form.setAttribute('action', '/login?to=' + escape(document.getElementById("targetLocation").content));

    var token_field = document.createElement('input');
    token_field.setAttribute('type', 'hidden');
    token_field.setAttribute('name', 'id_token');
    token_field.setAttribute('value', googleUser.getAuthResponse().id_token);

    form.appendChild(token_field);

    document.body.appendChild(form);
    form.submit();
}

function onFailure(error) {
    // FIXME
    alert(error.reason);
}

function renderButton() {
    gapi.load('auth2', function() {
        gapi.auth2.init({
            client_id: '1085640931155-0f6l02jv973og8mi4nb124k6qlrh470p.apps.googleusercontent.com'
        }).then(function() {
            gapi.signin2.render('goog-signin-button', {
                'width': 250,
                'height': 50,
                'longtitle': true,
                'onsuccess': onSuccess,
                'onfailure': onFailure
            });
        });
    });
}
