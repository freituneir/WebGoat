//main.js
/*
/js
js/main.js << main file for require.js
--/libs/(jquery,backbone,etc.) << base libs
--/goatApp/ << base dir for goat application, js-wise
--/goatApp/model
--/goatApp/view
--/goatApp/support
--/goatApp/controller
*/

/**
 * Main configuration for RequireJS. Referred to from Spring MVC /start.mvc using main_new.html template.
 * baseURL is the base path of all JavaScript libraries.
 * paths refers to the JavaScript Libraries that we want to use. A name and relative path is used. Extension .js is not required.
 *
 * jquery is a library that can easily access all objects on the HTML page.
 * jquery-ui is an UI extension on jquery and adds stuff like dialog boxes.
 * underscore contains a library of helper methods.
 * backbone contains models, events, key value bindings. Depends on jQuery and underscore
 * polyglot is a tiny i18n helper library
 */
require.config({
  baseUrl: "js/",
  paths: {
    jquery: 'libs/jquery.min',
    // These two used to resolve to jquery 2.1.4 and jquery-ui 1.10.4, which are shipped in
    // libs/ and carry known XSS issues (CVE-2015-9251, CVE-2016-7103). The aliases stay so
    // the modules requiring them keep loading, but they now resolve to the current builds.
    jqueryvuln: 'libs/jquery.min',
    jqueryuivuln: 'libs/jquery-ui.min',
    jqueryui: 'libs/jquery-ui.min',
    underscore: 'libs/underscore-min',
    backbone: 'libs/backbone-min',
    bootstrap: 'libs/bootstrap.min',
    text: 'libs/text',
    templates: 'goatApp/templates',
    polyglot: 'libs/polyglot.min',
    search: 'search'
  },

  deps: ['search'],

  shim: {
	"jqueryui": {
	  exports:"$",
	  deps: ['jquery']
	},
    underscore: {
      exports: "_"
    },
    bootstrap: {
	    deps: ['jquery'],
        exports: 'Bootstrap'
    },
    backbone: {
      deps: ['underscore', 'jquery'],
      exports: 'Backbone'
    }
  }
});

/*
 * Load and init the GoatApp. which is added here as a ADM asynchronous module definition.
 */
require([
	'jquery',
	'jqueryvuln',
	'jqueryui',
	'underscore',
	'backbone',
	'bootstrap',
	'goatApp/goatApp'], function($,jqueryVuln,jqueryui,_,Backbone,Bootstrap,Goat){
    // Every state changing call now has to carry the CSRF token the server handed out as a
    // cookie. Safe methods do not need one, and a call to another origin must never see it.
    $.ajaxPrefilter(function (options, originalOptions, xhr) {
        var method = (options.type || options.method || 'GET').toUpperCase();
        if (options.crossDomain || /^(GET|HEAD|OPTIONS|TRACE)$/.test(method)) {
            return;
        }
        var cookie = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
        if (cookie) {
            xhr.setRequestHeader('X-XSRF-TOKEN', decodeURIComponent(cookie[1]));
        }
    });
    Goat.initApp();
});
