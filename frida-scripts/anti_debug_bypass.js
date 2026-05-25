Java.perform(function() {
    'use strict';

    // Debug.isDebuggerConnected()
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            return false;
        };
    } catch(e) {}

    // ApplicationInfo.FLAG_DEBUGGABLE check
    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            var info = this.getApplicationInfo(pkg, flags);
            // Remove FLAG_DEBUGGABLE (0x2) from flags
            info.flags.value = info.flags.value & ~0x2;
            return info;
        };
    } catch(e) {}

    console.log('[lancer-anti-debug] Anti-debug bypass installed');
});
