Java.perform(function() {
    'use strict';

    // Runtime.exec bypass for su check
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
                throw Java.use('java.io.IOException').$new('File not found: ' + cmd);
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // File.exists() for common su paths
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var name = this.getAbsolutePath();
            var suPaths = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/data/local/xbin/su',
                          '/data/local/bin/su', '/system/sd/xbin/su', '/system/bin/failsafe/su',
                          '/data/local/su', '/su/bin/su'];
            if (suPaths.indexOf(name) !== -1) {
                console.log('[lancer-root] Hiding su path: ' + name);
                return false;
            }
            return this.exists();
        };
    } catch(e) {}

    // Build.TAGS check
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
    } catch(e) {}

    console.log('[lancer-root] Root detection bypass installed');
});
