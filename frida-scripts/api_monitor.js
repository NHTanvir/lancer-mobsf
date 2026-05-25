Java.perform(function() {
    'use strict';

    // Monitor SharedPreferences reads (may contain secrets)
    try {
        var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            if (result !== null && result.length > 0) {
                console.log('[lancer-api] SharedPreferences.getString key=' + key + ' value=' + result.substring(0, 50));
            }
            return result;
        };
    } catch(e) {}

    // Monitor Intent data
    try {
        var Intent = Java.use('android.content.Intent');
        Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
            console.log('[lancer-api] Intent.putExtra ' + name + '=' + (value ? value.substring(0, 50) : 'null'));
            return this.putExtra(name, value);
        };
    } catch(e) {}

    // Monitor HTTP connections
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            console.log('[lancer-api] URL.openConnection: ' + this.toString());
            return this.openConnection();
        };
    } catch(e) {}

    console.log('[lancer-api] API monitor installed');
});
